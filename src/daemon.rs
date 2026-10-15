use crate::system_host::SystemHost;
use crate::transaction::{self, Events, Outcome};
use crate::{protocol, verify};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

struct Options {
    socket: PathBuf,
    nix: PathBuf,
    nix_env: PathBuf,
    profile: PathBuf,
    static_keys: Vec<String>,
    key_file: Option<PathBuf>,
    update_uid: u32,
    before_hooks: Vec<PathBuf>,
    after_hooks: Vec<PathBuf>,
    report_queue: PathBuf,
    artifact_prepare: Option<PathBuf>,
    artifact_activate: Option<PathBuf>,
    artifact_prepare_args: Vec<String>,
    artifact_activate_args: Vec<String>,
    reboot_command: Option<PathBuf>,
    restart_command: Option<PathBuf>,
    restart_args: Vec<String>,
    systemctl: Option<PathBuf>,
    state_dir: PathBuf,
    /// Where the phase of a transaction in progress is published to the
    /// update account.
    phase_file: PathBuf,
    ssh_ports: Vec<u16>,
    health_units: Vec<String>,
    health_settle: Duration,
    health_timeout: Duration,
    /// Units started, without waiting, after each committed closure switch.
    commit_units: Vec<String>,
    /// Names the committed system whose post-commit units may not have
    /// started yet. It lives where the system profile does, so it survives
    /// a reboot whenever the commit does.
    commit_units_pending: PathBuf,
}

impl Options {
    fn host(&self) -> Result<SystemHost<'_>, String> {
        Ok(SystemHost {
            nix_env: &self.nix_env,
            profile: &self.profile,
            systemctl: self.systemctl.as_deref().ok_or("missing --systemctl")?,
            state_dir: &self.state_dir,
            phase_file: &self.phase_file,
            ssh_ports: &self.ssh_ports,
            health_units: &self.health_units,
            settle: self.health_settle,
            health_timeout: self.health_timeout,
        })
    }
}

/// Reports transaction progress where no client listens.
struct LogEvents;
impl Events for LogEvents {
    fn activated(&mut self, _: &Path) {}
    fn warning(&mut self, _: &str) {}
    fn failed(&mut self, reason: &str) {
        eprintln!("nix-update-remote: {reason}; rolling back");
    }
    fn waiting(&mut self, _: &str) {}
}

/// Reports transaction progress to the client. A client that went away does
/// not stop the transaction; its lines are dropped.
struct StreamEvents<'a>(&'a mut UnixStream);
impl StreamEvents<'_> {
    fn line(&mut self, text: String) {
        let _ = self.0.write_all(text.as_bytes());
        let _ = self.0.flush();
    }
}
impl Events for StreamEvents<'_> {
    fn activated(&mut self, system: &Path) {
        self.line(format!("ACTIVATED {}\n", system.display()));
    }
    fn failed(&mut self, reason: &str) {
        eprintln!("nix-update-remote: {reason}; rolling back");
        self.line(format!("FAILED {}\n", protocol::one_line(reason)));
    }
    fn waiting(&mut self, phase: &str) {
        self.line(format!("WAITING {}\n", protocol::one_line(phase)));
    }
    fn warning(&mut self, text: &str) {
        self.line(format!("WARNING {}\n", protocol::one_line(text)));
    }
    fn stage(&mut self, stage: transaction::Stage) {
        self.line(stage.line());
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    if !rustix::process::geteuid().is_root() {
        return Err("daemon role must run as root".into());
    }
    let mut follow = Follow::start(&options);
    if options.artifact_prepare.is_none() {
        // A switch that an earlier daemon left unfinished is undone before
        // the next update can start.
        let mut host = options.host()?;
        if let Some((journal, outcome)) = transaction::recover(&mut host, &mut LogEvents) {
            let result = report_outcome(&outcome);
            record_event(&options, &journal.new_system, "after", result);
        }
        if let Err(error) = host.republish_phase() {
            eprintln!("nix-update-remote: {error}");
        }
        resume_commit_units(&options, Path::new("/run/current-system"));
    }
    // The rollback may have left a system with another updater.
    follow.check(&options);
    protocol::remove_stale_socket(&options.socket)?;
    let listener = UnixListener::bind(&options.socket).map_err(|error| error.to_string())?;
    fs::set_permissions(&options.socket, fs::Permissions::from_mode(0o660))
        .map_err(|error| error.to_string())?;
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                handle(stream, &options, &mut follow);
                follow.check(&options);
            }
            Err(error) => eprintln!("nix-update-remote: accept failed: {error}"),
        }
    }
    Ok(())
}

/// The update account's login program comes from here: sshd runs the shell
/// it names, so it is the updater of the current system.
const PASSWD: &str = "/etc/passwd";

/// The login shell `passwd` gives the account with `uid`.
fn login_shell(passwd: &str, uid: u32) -> Result<PathBuf, String> {
    let shell = passwd
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|fields| fields.len() == 7 && fields[2].parse::<u32>().ok() == Some(uid))
        .map(|fields| PathBuf::from(fields[6]))
        .ok_or_else(|| format!("{PASSWD} has no account with UID {uid}"))?;
    if !shell.is_absolute() {
        return Err(format!("the login shell of UID {uid} is not an absolute path"));
    }
    Ok(shell)
}

/// The daemon runs another binary than the login program of the current
/// system, so the peer check refuses every login helper. That happens when
/// the system changed without restarting the daemon: a switch outside the
/// updater, or the rollback of an interrupted switch at start.
struct Skew {
    running: PathBuf,
    current: PathBuf,
}

impl Skew {
    fn of(update_uid: u32) -> Result<Option<Skew>, String> {
        let passwd = fs::read_to_string(PASSWD).map_err(|e| format!("{PASSWD}: {e}"))?;
        let helper = login_shell(&passwd, update_uid)?;
        let current = fs::metadata(&helper).map_err(|e| format!("{}: {e}", helper.display()))?;
        let own = fs::metadata("/proc/self/exe").map_err(|e| e.to_string())?;
        if (own.dev(), own.ino()) == (current.dev(), current.ino()) {
            return Ok(None);
        }
        Ok(Some(Skew {
            running: fs::read_link("/proc/self/exe").unwrap_or_else(|_| "an unknown binary".into()),
            current: fs::canonicalize(&helper).unwrap_or(helper),
        }))
    }

    fn describe(&self) -> String {
        format!(
            "the update daemon runs {}, but the update login of the current system is {}",
            self.running.display(),
            self.current.display()
        )
    }
}

/// Keeps the daemon on the updater binary of the current system.
struct Follow {
    /// The service started this binary although it is not the current
    /// system's; restarting it would start the same one again.
    stuck: bool,
    restart_requested: bool,
}

impl Follow {
    fn start(options: &Options) -> Self {
        let stuck = match Skew::of(options.update_uid) {
            Ok(Some(skew)) => {
                eprintln!(
                    "nix-update-remote: {}; nix-update-remote.service does not start the current system's updater, \
                     so every update login will be refused",
                    skew.describe()
                );
                true
            }
            Ok(None) => false,
            Err(error) => {
                eprintln!("nix-update-remote: cannot compare with the current system's updater: {error}");
                false
            }
        };
        Self { stuck, restart_requested: false }
    }

    /// The skew, if the daemon must not serve updates as it is.
    fn skew(&self, options: &Options) -> Option<Skew> {
        Skew::of(options.update_uid).ok().flatten()
    }

    /// Restarts into the current system's updater when the system changed
    /// under this daemon. Returns whether a restart is on its way.
    fn check(&mut self, options: &Options) -> bool {
        if self.restart_requested {
            return true;
        }
        if self.stuck {
            return false;
        }
        let Some(skew) = self.skew(options) else {
            return false;
        };
        eprintln!("nix-update-remote: {}; restarting into the current updater", skew.describe());
        match &options.restart_command {
            Some(command) => match verify::checked(
                Command::new(command).args(&options.restart_args),
                "requesting broker restart",
            ) {
                Ok(()) => self.restart_requested = true,
                Err(error) => {
                    eprintln!("nix-update-remote: {error}");
                    self.stuck = true;
                }
            },
            // The service manager restarts a daemon that failed.
            None => std::process::exit(1),
        }
        self.restart_requested
    }

    /// Answers a login helper that reached a daemon on the wrong binary:
    /// `RETRY` while the daemon restarts into the current updater, else a
    /// rejection that names both binaries. Returns whether it answered.
    fn answer(&mut self, stream: &mut UnixStream, options: &Options) -> bool {
        let Some(skew) = self.skew(options) else {
            return false;
        };
        // The restart stops this daemon at once, so the answer goes first.
        let restart = self.restart_requested || !self.stuck;
        let line = if restart {
            format!("{} {}; restarting into the current updater\n", protocol::RETRY, protocol::one_line(&skew.describe()))
        } else {
            format!(
                "REJECTED {}\n",
                protocol::one_line(&format!(
                    "{}; restart nix-update-remote.service and make it run the current system's updater",
                    skew.describe()
                ))
            )
        };
        eprintln!("nix-update-remote: refused an update login: {}", skew.describe());
        // Closing with the request unread would reset the connection before
        // the login helper reads the answer.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = (&mut *stream).take(protocol::MAX_REQUEST).read_to_end(&mut Vec::new());
        let _ = stream.write_all(line.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        if restart {
            self.check(options);
        }
        true
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut socket = PathBuf::from(protocol::SOCKET);
    let mut nix = None;
    let mut nix_env = None;
    let mut profile = PathBuf::from("/nix/var/nix/profiles/system");
    let mut static_keys = Vec::new();
    let mut key_file = None;
    let mut update_uid = None;
    let mut hook_uid = None;
    let mut hook_gid = None;
    let mut before_hooks = Vec::new();
    let mut after_hooks = Vec::new();
    let mut report_queue = PathBuf::from("/persistent/system-update-reports");
    let mut artifact_prepare = None;
    let mut artifact_activate = None;
    let mut reboot_command = None;
    let mut restart_command = None;
    let mut restart_args = Vec::new();
    let mut artifact_prepare_args = Vec::new();
    let mut artifact_activate_args = Vec::new();
    let mut systemctl = None;
    let mut state_dir = PathBuf::from("/var/lib/nix-update-remote");
    let phase_file = PathBuf::from(protocol::PHASE_FILE);
    let mut ssh_ports = Vec::new();
    let mut health_units = Vec::new();
    let mut health_settle = Duration::from_secs(10);
    let mut health_timeout = Duration::from_secs(600);
    let mut commit_units = Vec::new();
    let mut commit_units_pending = PathBuf::from(COMMIT_UNITS_PENDING);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--systemctl" => systemctl = Some(next_path(&mut iter, arg)?),
            "--state-dir" => state_dir = next_path(&mut iter, arg)?,
            "--ssh-port" => ssh_ports.push(
                next_value(&mut iter, arg)?
                    .parse()
                    .map_err(|_| "invalid SSH port")?,
            ),
            "--health-unit" => {
                let unit = next_value(&mut iter, arg)?;
                if unit.starts_with('-') || unit.is_empty() || unit.contains(char::is_whitespace) {
                    return Err("invalid health unit".into());
                }
                health_units.push(unit);
            }
            "--health-settle-seconds" => {
                health_settle = Duration::from_secs(
                    next_value(&mut iter, arg)?
                        .parse()
                        .map_err(|_| "invalid settle time")?,
                )
            }
            "--health-timeout-seconds" => {
                health_timeout = Duration::from_secs(
                    next_value(&mut iter, arg)?
                        .parse()
                        .map_err(|_| "invalid health timeout")?,
                )
            }
            "--commit-units-pending" => commit_units_pending = next_path(&mut iter, arg)?,
            "--commit-unit" => {
                let unit = next_value(&mut iter, arg)?;
                if !valid_unit_name(&unit) {
                    return Err("invalid commit unit".into());
                }
                commit_units.push(unit);
            }
            "--artifact-prepare-arg" => artifact_prepare_args.push(next_value(&mut iter, arg)?),
            "--artifact-activate-arg" => artifact_activate_args.push(next_value(&mut iter, arg)?),
            "--artifact-prepare" => artifact_prepare = Some(next_path(&mut iter, arg)?),
            "--artifact-activate" => artifact_activate = Some(next_path(&mut iter, arg)?),
            "--reboot-command" => reboot_command = Some(next_path(&mut iter, arg)?),
            "--socket" => socket = next_path(&mut iter, arg)?,
            "--nix" => nix = Some(next_path(&mut iter, arg)?),
            "--nix-env" => nix_env = Some(next_path(&mut iter, arg)?),
            "--profile" => profile = next_path(&mut iter, arg)?,
            "--trusted-key" => static_keys.push(next_value(&mut iter, arg)?),
            "--trusted-key-file" => key_file = Some(next_path(&mut iter, arg)?),
            "--update-uid" => {
                update_uid = Some(
                    next_value(&mut iter, arg)?
                        .parse()
                        .map_err(|_| "invalid update UID")?,
                )
            }
            "--hook-uid" => {
                hook_uid = Some(
                    next_value(&mut iter, arg)?
                        .parse()
                        .map_err(|_| "invalid hook UID")?,
                )
            }
            "--hook-gid" => {
                hook_gid = Some(
                    next_value(&mut iter, arg)?
                        .parse()
                        .map_err(|_| "invalid hook GID")?,
                )
            }
            "--before-hook" => before_hooks.push(next_path(&mut iter, arg)?),
            "--after-hook" => after_hooks.push(next_path(&mut iter, arg)?),
            "--hook-path" => {
                let _ = next_value(&mut iter, arg)?;
            }
            "--report-queue" => report_queue = next_path(&mut iter, arg)?,
            "--restart-command" => restart_command = Some(next_path(&mut iter, arg)?),
            "--restart-arg" => restart_args.push(next_value(&mut iter, arg)?),
            _ => return Err(format!("unknown daemon argument: {arg}")),
        }
    }
    if artifact_prepare.is_some() != artifact_activate.is_some() {
        return Err("artifact backend requires prepare and activate executables".into());
    }
    if !commit_units.is_empty() && artifact_prepare.is_some() {
        return Err("post-commit units apply only to closure updates".into());
    }
    if artifact_prepare.is_none() && systemctl.is_none() {
        return Err("closure updates require --systemctl for their health checks".into());
    }
    if !state_dir.is_absolute() {
        return Err("state directory must be absolute".into());
    }
    if !commit_units_pending.is_absolute() || commit_units_pending.starts_with("/nix/store") {
        return Err("the pending post-commit units file must be an absolute mutable path".into());
    }
    for command in artifact_prepare
        .iter()
        .chain(artifact_activate.iter())
        .chain(reboot_command.iter())
        .chain(restart_command.iter())
        .chain(systemctl.iter())
    {
        if !command.starts_with("/nix/store/") || !command.is_absolute() {
            return Err("backend commands must be immutable Nix store executables".into());
        }
    }
    if artifact_prepare.is_none() && static_keys.is_empty() && key_file.is_none() {
        return Err("daemon requires a trust key".into());
    }
    if (!before_hooks.is_empty() || !after_hooks.is_empty())
        && (hook_uid.is_none() || hook_gid.is_none())
    {
        return Err("hooks require an unprivileged UID and GID".into());
    }
    if hook_uid == Some(0) || hook_gid == Some(0) {
        return Err("hooks must not run as root".into());
    }
    for hook in before_hooks.iter().chain(after_hooks.iter()) {
        if !hook.starts_with("/nix/store/") || !hook.is_absolute() {
            return Err("hooks must be immutable Nix store executables".into());
        }
    }
    Ok(Options {
        socket,
        nix: nix.ok_or("missing --nix")?,
        nix_env: nix_env.ok_or("missing --nix-env")?,
        profile,
        static_keys,
        key_file,
        update_uid: update_uid.ok_or("missing --update-uid")?,
        before_hooks,
        after_hooks,
        report_queue,
        artifact_prepare,
        artifact_activate,
        artifact_prepare_args,
        artifact_activate_args,
        reboot_command,
        restart_command,
        restart_args,
        systemctl,
        state_dir,
        phase_file,
        ssh_ports,
        health_units,
        health_settle,
        health_timeout,
        commit_units,
        commit_units_pending,
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<String, String> {
    iter.next()
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn next_path<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    name: &str,
) -> Result<PathBuf, String> {
    next_value(iter, name).map(PathBuf::from)
}

/// How one request ended, as the client is told.
enum Reply {
    Switched(PathBuf, bool),
    /// Nothing changed on the host.
    Rejected(String),
    RolledBack(String),
    RollbackFailed(String),
    /// The answer to a probe; nothing changed.
    Pong,
}

fn report_outcome(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Committed { warnings } => {
            for warning in warnings {
                eprintln!("nix-update-remote: warning: {warning}");
            }
            "success"
        }
        Outcome::RolledBack { failure, detail } => {
            eprintln!("nix-update-remote: rolled back update: {failure}; {detail}");
            "rolled-back"
        }
        Outcome::RollbackFailed { failure, problems } => {
            eprintln!("nix-update-remote: ROLLBACK FAILED after: {failure}; {problems}");
            "rollback-failed"
        }
    }
}

fn handle(mut stream: UnixStream, options: &Options, follow: &mut Follow) {
    let previous_system = fs::read_link("/run/current-system").ok();
    // A stalled client must not hold up the transaction.
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    // The peer check below would refuse the current login helper.
    if update_account_peer(&stream, options.update_uid) && follow.answer(&mut stream, options) {
        return;
    }
    let (reply, switch) = apply_request(&mut stream, options);
    let response = match &reply {
        Reply::Switched(path, _) => format!("OK {}\n", path.display()),
        Reply::Rejected(error) => {
            eprintln!("nix-update-remote: rejected update: {error}");
            if switch {
                format!("REJECTED {}\n", protocol::one_line(error))
            } else {
                "ERR update rejected\n".into()
            }
        }
        Reply::RolledBack(text) => format!("ROLLED-BACK {}\n", protocol::one_line(text)),
        Reply::RollbackFailed(text) => format!("ROLLBACK-FAILED {}\n", protocol::one_line(text)),
        Reply::Pong => protocol::pong(
            &fs::read_link("/proc/self/exe").unwrap_or_else(|_| PathBuf::from("/proc/self/exe")),
        ),
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if switch && matches!(reply, Reply::Switched(_, false)) {
        start_commit_units(options);
    }
    if matches!(reply, Reply::Switched(_, true)) {
        if let Some(command) = &options.reboot_command {
            if let Err(error) = verify::checked(
                Command::new(command).args(["--no-block", "reboot"]),
                "requesting reboot",
            ) {
                eprintln!("nix-update-remote: {error}");
            }
        }
    } else if matches!(reply, Reply::Switched(..))
        || fs::read_link("/run/current-system").ok() != previous_system
    {
        // A switch that could not be undone can still install a new login
        // helper and broker configuration. Refresh after replying in that
        // case too, so a retry uses matching binaries.
        if let Some(command) = &options.restart_command {
            match verify::checked(
                Command::new(command).args(&options.restart_args),
                "requesting broker restart",
            ) {
                Ok(()) => follow.restart_requested = true,
                Err(error) => eprintln!("nix-update-remote: {error}"),
            }
        }
    }
}

/// A systemd unit name the daemon may start: no option, no glob, no path.
fn valid_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 255
        && !unit.starts_with('-')
        && unit.contains('.')
        && unit.bytes().all(|byte| byte.is_ascii_alphanumeric() || b":-_.@\\".contains(&byte))
}

/// Where the pending post-commit units are recorded by default: next to the
/// system profile, on whatever keeps `/nix/var` across reboots.
const COMMIT_UNITS_PENDING: &str = "/nix/var/nix-update-remote/commit-units-pending";

/// Starts the post-commit units, such as verifications of what the commit
/// installed. They run on their own; their failure is theirs to report and
/// never changes the update's outcome. Once they are started, nothing is
/// pending any more.
fn start_commit_units(options: &Options) {
    let (Some(systemctl), false) = (&options.systemctl, options.commit_units.is_empty()) else {
        return;
    };
    let result = verify::checked(
        Command::new(systemctl)
            .args(["start", "--no-block", "--"])
            .args(&options.commit_units),
        "starting the post-commit units",
    )
    .and_then(|()| clear_pending(&options.commit_units_pending));
    if let Err(error) = result {
        eprintln!("nix-update-remote: {error}");
    }
}

/// Records, before the switch, that `system`'s post-commit units are due
/// once it commits: a reboot or a daemon stop between the commit and their
/// start must not skip them.
fn mark_pending(file: &Path, system: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let error = |e: std::io::Error| format!("recording the pending post-commit units in {}: {e}", file.display());
    let directory = file.parent().ok_or("the pending post-commit units file has no directory")?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory).map_err(error)?;
    let temporary = file.with_extension("new");
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(error)?;
    out.write_all(format!("{}\n", system.display()).as_bytes()).map_err(error)?;
    out.sync_all().map_err(error)?;
    fs::rename(&temporary, file).map_err(error)?;
    fs::File::open(directory).and_then(|d| d.sync_all()).map_err(error)
}

fn read_pending(file: &Path) -> Result<Option<PathBuf>, String> {
    match fs::read_to_string(file) {
        Ok(text) => Ok(Some(PathBuf::from(text.trim_end_matches('\n')))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", file.display())),
    }
}

fn clear_pending(file: &Path) -> Result<(), String> {
    match fs::remove_file(file) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("clearing {}: {error}", file.display()))
        }
        _ => Ok(()),
    }
}

/// Switches to `resolved` with the post-commit units marked pending until
/// the commit's units start; a switch that did not commit leaves nothing
/// pending.
fn switch_marked(
    options: &Options,
    host: &mut dyn transaction::Host,
    resolved: &Path,
    events: &mut dyn Events,
) -> Result<Outcome, String> {
    if !options.commit_units.is_empty() {
        mark_pending(&options.commit_units_pending, resolved)?;
    }
    let outcome = transaction::update(host, resolved, events);
    if !matches!(outcome, Ok(Outcome::Committed { .. }))
        && !options.commit_units.is_empty()
        && let Err(error) = clear_pending(&options.commit_units_pending)
    {
        eprintln!("nix-update-remote: {error}");
    }
    outcome
}

/// At daemon start, typically after a reboot: starts the post-commit units
/// of a commit whose units never started, if the host runs that system and
/// its profile names it. A pending mark of any other system is dropped: its
/// switch did not commit, or another system replaced it.
fn resume_commit_units(options: &Options, current: &Path) {
    let pending = match read_pending(&options.commit_units_pending) {
        Ok(Some(pending)) => pending,
        Ok(None) => return,
        Err(error) => {
            eprintln!("nix-update-remote: cannot read the pending post-commit units: {error}");
            return;
        }
    };
    let canonical = |path: &Path| fs::canonicalize(path).ok();
    let system = canonical(&pending);
    if !options.commit_units.is_empty()
        && system.is_some()
        && system == canonical(current)
        && system == canonical(&options.profile)
    {
        eprintln!(
            "nix-update-remote: starting the post-commit units of {}, which committed before they started",
            pending.display()
        );
        start_commit_units(options);
    } else if let Err(error) = clear_pending(&options.commit_units_pending) {
        eprintln!("nix-update-remote: {error}");
    }
}

/// Whether the peer runs as the update account; only its logins may make
/// the daemon restart.
fn update_account_peer(stream: &UnixStream, expected_uid: u32) -> bool {
    rustix::net::sockopt::socket_peercred(stream)
        .is_ok_and(|credentials| credentials.uid.as_raw() == expected_uid)
}

/// Returns the reply and whether the request was a closure switch.
fn apply_request(stream: &mut UnixStream, options: &Options) -> (Reply, bool) {
    let operation = (|| {
        authenticate_peer(stream, options.update_uid)?;
        if protocol::read_control_line(stream)? != protocol::MAGIC {
            return Err("invalid protocol header".to_owned());
        }
        protocol::read_control_line(stream)
    })();
    match operation.as_deref() {
        Err(error) => (Reply::Rejected(error.clone()), false),
        Ok("ARTIFACT") => (
            match apply_artifact(stream, options) {
                Ok((path, reboot)) => Reply::Switched(path, reboot),
                Err(error) => Reply::Rejected(error),
            },
            false,
        ),
        Ok("SWITCH") if options.artifact_prepare.is_none() => (apply_switch(stream, options), true),
        // The peer check above already passed: that is what a probe proves.
        Ok("PING") => (Reply::Pong, false),
        Ok(_) => (Reply::Rejected("operation is disabled for this backend".into()), false),
    }
}

fn verified_switch_request(stream: &mut UnixStream, options: &Options) -> Result<PathBuf, String> {
    let mut bytes = Vec::new();
    (&mut *stream)
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    authenticate_peer(stream, options.update_uid)?;
    let tail = String::from_utf8(bytes).map_err(|_| "request is not UTF-8")?;
    let requested = protocol::parse_request(&format!("{}\nSWITCH\n{tail}", protocol::MAGIC))?;
    StreamEvents(stream).stage(transaction::Stage::Verifying);
    let resolved = verify::system(&requested)?;
    verify::closure(
        &options.nix,
        &resolved,
        &options.static_keys,
        options.key_file.as_deref(),
    )?;
    Ok(resolved)
}

fn apply_switch(stream: &mut UnixStream, options: &Options) -> Reply {
    // Verification precedes every change: a closure that fails it leaves
    // the profile, the bootloader and the running system untouched.
    let resolved = match verified_switch_request(stream, options) {
        Ok(resolved) => resolved,
        Err(error) => return Reply::Rejected(error),
    };
    let mut host = match options.host() {
        Ok(host) => host,
        Err(error) => return Reply::Rejected(error),
    };
    record_event(options, &resolved, "before", "pending");
    let outcome = switch_marked(options, &mut host, &resolved, &mut StreamEvents(stream));
    let (result, reply) = match outcome {
        Err(error) => ("failure", Reply::Rejected(error)),
        Ok(outcome) => {
            let result = report_outcome(&outcome);
            (result, match outcome {
                Outcome::Committed { .. } => Reply::Switched(resolved.clone(), false),
                Outcome::RolledBack { failure, detail } => {
                    Reply::RolledBack(format!("{failure}; {detail}"))
                }
                Outcome::RollbackFailed { failure, problems } => Reply::RollbackFailed(format!(
                    "{failure}; the rollback could not be verified: {problems}"
                )),
            })
        }
    };
    record_event(options, &resolved, "after", result);
    reply
}

fn apply_artifact(stream: &mut UnixStream, options: &Options) -> Result<(PathBuf, bool), String> {
    let prepare = options
        .artifact_prepare
        .as_ref()
        .ok_or("artifact backend is disabled")?;
    let activate = options
        .artifact_activate
        .as_ref()
        .ok_or("artifact activation is missing")?;
    let input: OwnedFd = stream.try_clone().map_err(|e| e.to_string())?.into();
    let mut child = Command::new(prepare)
        .args(&options.artifact_prepare_args)
        .env_clear()
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut receipt = Vec::new();
    child
        .stdout
        .take()
        .ok_or("backend stdout missing")?
        .take(protocol::MAX_REQUEST + 1)
        .read_to_end(&mut receipt)
        .map_err(|e| e.to_string())?;
    if receipt.len() > protocol::MAX_REQUEST as usize {
        let _ = child.kill();
        let _ = child.wait();
        return Err("backend receipt exceeds size limit".into());
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    authenticate_peer(stream, options.update_uid)?;
    if !status.success() {
        record_event(
            options,
            std::path::Path::new("unverified-artifact"),
            "after",
            "failure",
        );
        return Err("artifact verification/staging failed".into());
    }
    let (system, reboot) = protocol::parse_artifact_receipt(&receipt)?;
    if reboot && options.reboot_command.is_none() {
        return Err("reboot requested but no reboot command configured".into());
    }
    record_event(options, &system, "before", "pending");
    let activation = verify::checked(
        Command::new(activate)
            .args(&options.artifact_activate_args)
            .env_clear()
            .arg(&system),
        "activating artifact",
    );
    let result = if activation.is_ok() {
        "success"
    } else {
        "failure"
    };
    record_event(options, &system, "after", result);
    activation?;
    Ok((system, reboot))
}

fn record_event(options: &Options, system: &std::path::Path, phase: &str, result: &str) {
    if options.before_hooks.is_empty() && options.after_hooks.is_empty() {
        return;
    }
    if let Err(error) = crate::report_queue::record(&options.report_queue, system, phase, result) {
        eprintln!("nix-update-remote: cannot persist {phase} update notification: {error}");
    }
}

fn authenticate_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|e| e.to_string())?;
    if credentials.uid.as_raw() != expected_uid {
        return Err("control peer has the wrong UID".into());
    }
    let peer_exe = PathBuf::from(format!("/proc/{}/exe", credentials.pid.as_raw_nonzero()));
    let peer = fs::metadata(&peer_exe).map_err(|error| error.to_string())?;
    let own = fs::metadata("/proc/self/exe").map_err(|error| error.to_string())?;
    if peer.dev() != own.dev() || peer.ino() != own.ino() {
        let name = |path: &Path| {
            fs::read_link(path).map_or_else(|_| "an unknown binary".to_owned(), |p| p.display().to_string())
        };
        return Err(format!(
            "control peer {} is not this updater binary {}; a login that started before the last \
             switch must reconnect",
            name(&peer_exe),
            name(Path::new("/proc/self/exe"))
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::fake::{FakeHost, path, system};

    #[test]
    fn the_current_updater_is_the_login_shell_of_the_update_account() {
        let passwd = "root:x:0:0::/root:/run/current-system/sw/bin/bash\nupdate:x:2990:2990::/var/empty:/nix/store/aaa-nix-update-remote/bin/nix-update-remote\n";
        assert_eq!(login_shell(passwd, 2990).unwrap(), Path::new("/nix/store/aaa-nix-update-remote/bin/nix-update-remote"));
        assert!(login_shell(passwd, 2991).is_err());
        assert!(login_shell("update:x:2990:2990::/var/empty:relative\n", 2990).is_err());
    }

    fn options(extra: &[&str]) -> Result<Options, String> {
        let uid = rustix::process::getuid().as_raw().to_string();
        let mut args: Vec<String> = [
            "--nix", "/nix/store/x-nix/bin/nix", "--nix-env", "/nix/store/x-nix/bin/nix-env",
            "--update-uid", &uid, "--systemctl", "/nix/store/x-systemd/bin/systemctl",
            "--trusted-key", "update:AAAA",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.extend(extra.iter().map(|s| s.to_string()));
        parse(&args)
    }

    #[test]
    fn a_ping_from_this_updater_binary_gets_a_pong_and_changes_nothing() {
        let options = options(&[]).unwrap();
        let (mut daemon_side, mut client) = UnixStream::pair().unwrap();
        client.write_all(protocol::ping_request().as_bytes()).unwrap();
        let (reply, switch) = apply_request(&mut daemon_side, &options);
        assert!(matches!(reply, Reply::Pong), "the probe was not answered");
        assert!(!switch);
        // A peer under another UID fails the same peer check as an update.
        let other = Options { update_uid: options.update_uid + 1, ..options };
        let (mut daemon_side, mut client) = UnixStream::pair().unwrap();
        client.write_all(protocol::ping_request().as_bytes()).unwrap();
        assert!(matches!(apply_request(&mut daemon_side, &other).0, Reply::Rejected(_)));
    }

    #[test]
    fn commit_units_are_plain_unit_names_for_closure_updates_only() {
        let parsed = options(&["--commit-unit", "nmbl-rescue-verify.service"]).unwrap();
        assert_eq!(parsed.commit_units, ["nmbl-rescue-verify.service"]);
        for bad in ["-x.service", "a b.service", "*.service", "../x.service", "noext", ""] {
            assert!(options(&["--commit-unit", bad]).is_err(), "{bad:?}");
        }
        assert!(options(&[
            "--commit-unit", "a.service",
            "--artifact-prepare", "/nix/store/p", "--artifact-activate", "/nix/store/a",
        ])
        .is_err());
    }

    #[test]
    fn a_vanished_client_does_not_stop_the_switch_or_its_rollback() {
        for broken in [false, true] {
            let (mut daemon_side, client) = UnixStream::pair().unwrap();
            drop(client);
            let mut new = system(&["sshd.service", "app.service"]);
            if broken {
                new.failing.insert("app.service".into());
            }
            let mut host = FakeHost::running(("old", system(&["sshd.service"])), ("new", new));
            let outcome = transaction::update(&mut host, &path("new"), &mut StreamEvents(&mut daemon_side)).unwrap();
            if broken {
                assert!(matches!(outcome, Outcome::RolledBack { .. }), "{outcome:?}");
                assert_eq!(host.profile_system(), Some(path("old")));
            } else {
                assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
                assert_eq!(host.profile_system(), Some(path("new")));
            }
            assert_eq!(host.journal, None);
        }
    }
}

#[cfg(test)]
mod pending_tests {
    use super::*;
    use crate::transaction::fake::{FakeHost, path, system};
    use std::os::unix::fs::symlink;

    /// Options whose systemctl records its arguments and exits with `code`.
    fn options(directory: &Path, code: i32) -> Options {
        let systemctl = directory.join(format!("systemctl-{code}"));
        fs::write(&systemctl, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nexit {code}\n", directory.join("started").display())).unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = rustix::process::getuid().as_raw().to_string();
        let pending = directory.join("var/commit-units-pending");
        let args: Vec<String> = [
            "--nix", "/nix/store/x-nix/bin/nix", "--nix-env", "/nix/store/x-nix/bin/nix-env",
            "--update-uid", &uid, "--systemctl", "/nix/store/x-systemd/bin/systemctl",
            "--trusted-key", "update:AAAA", "--commit-unit", "rescue-verify.service",
            "--commit-units-pending", pending.to_str().unwrap(),
        ]
        .map(String::from)
        .to_vec();
        Options { systemctl: Some(systemctl), profile: directory.join("system"), ..parse(&args).unwrap() }
    }

    fn started(directory: &Path) -> String {
        fs::read_to_string(directory.join("started")).unwrap_or_default()
    }

    #[test]
    fn post_commit_units_start_on_the_next_boot_after_a_reboot_skipped_them() {
        let (Some(a), Some(b)) = (std::env::var_os("NIX_UPDATE_TEST_NIX"), std::env::var_os("NIX_UPDATE_TEST_COREUTILS")) else {
            panic!("NIX_UPDATE_TEST_NIX and NIX_UPDATE_TEST_COREUTILS must name store paths");
        };
        let directory = std::env::temp_dir().join(format!("nur-pending-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let options = options(&directory, 0);
        let pending = options.commit_units_pending.clone();

        // A switch that commits leaves its units pending until they start:
        // a reboot right after the commit keeps the mark.
        let mut host = FakeHost::running(("old", system(&["sshd.service"])), ("new", system(&["sshd.service"])));
        let outcome = switch_marked(&options, &mut host, &path("new"), &mut LogEvents).unwrap();
        assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
        assert_eq!(read_pending(&pending).unwrap(), Some(path("new")));
        // A switch that rolls back leaves nothing pending.
        let mut broken = system(&["sshd.service", "app.service"]);
        broken.failing.insert("app.service".into());
        let mut host = FakeHost::running(("old", system(&["sshd.service"])), ("new", broken));
        let outcome = switch_marked(&options, &mut host, &path("new"), &mut LogEvents).unwrap();
        assert!(matches!(outcome, Outcome::RolledBack { .. }), "{outcome:?}");
        assert_eq!(read_pending(&pending).unwrap(), None);

        // The next boot runs the committed system A: its units start once.
        let current = directory.join("current-system");
        symlink(&a, &current).unwrap();
        symlink(&a, directory.join("system-2-link")).unwrap();
        symlink("system-2-link", directory.join("system")).unwrap();
        mark_pending(&pending, Path::new(&a)).unwrap();
        resume_commit_units(&options, &current);
        assert_eq!(started(&directory), "start\n--no-block\n--\nrescue-verify.service\n");
        assert_eq!(read_pending(&pending).unwrap(), None);
        resume_commit_units(&options, &current);
        assert_eq!(started(&directory).lines().count(), 4, "started twice");

        // The boot came up on another system: the switch did not commit.
        fs::remove_file(directory.join("started")).unwrap();
        mark_pending(&pending, Path::new(&b)).unwrap();
        resume_commit_units(&options, &current);
        assert_eq!(started(&directory), "");
        assert_eq!(read_pending(&pending).unwrap(), None);

        // Units that could not be started stay pending for the next start.
        let failing = Options { systemctl: self::options(&directory, 1).systemctl, ..options };
        mark_pending(&pending, Path::new(&a)).unwrap();
        resume_commit_units(&failing, &current);
        assert!(started(&directory).contains("rescue-verify.service"));
        assert_eq!(read_pending(&pending).unwrap(), Some(PathBuf::from(&a)));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn the_pending_file_is_mutable_and_absolute() {
        let uid = rustix::process::getuid().as_raw().to_string();
        let base = ["--nix", "/nix/store/x/bin/nix", "--nix-env", "/nix/store/x/bin/nix-env", "--update-uid", &uid,
            "--systemctl", "/nix/store/s/bin/systemctl", "--trusted-key", "update:AAAA"];
        let with = |file: &str| parse(&[&base[..], &["--commit-units-pending", file]].concat().iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(with("relative").is_err());
        assert!(with("/nix/store/x-pending").is_err());
        assert_eq!(with("/persistent/pending").unwrap().commit_units_pending, Path::new("/persistent/pending"));
        assert_eq!(parse(&base.map(String::from)).unwrap().commit_units_pending, Path::new(COMMIT_UNITS_PENDING));
    }
}
