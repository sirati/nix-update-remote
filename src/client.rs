use crate::cancellation::ManagedCommand;
use crate::protocol;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Options {
    target: String,
    installable: String,
    signing_key: Option<PathBuf>,
    key_command: Option<PathBuf>,
    key_args: Vec<String>,
    sign_command: Option<PathBuf>,
    sign_args: Vec<String>,
    impure: bool,
    activation_command: Option<PathBuf>,
    activation_args: Vec<String>,
    post_command: Option<PathBuf>,
    post_args: Vec<String>,
    ssh_args: Vec<String>,
    login_approval: crate::login_approval::LoginApproval,
    failure_command: Option<PathBuf>,
    failure_args: Vec<String>,
    warning_command: Option<PathBuf>,
    warning_args: Vec<String>,
    progress_command: Option<PathBuf>,
    progress_args: Vec<String>,
    /// Nix public keys whose existing signatures on closure paths are used
    /// instead of asking the external signer again.
    reuse_signature_keys: Vec<String>,
}

pub fn deploy(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    let result = deploy_with(&options);
    if let Err(error) = &result {
        // Every failure stops the update here, before any later step.
        report_failure(&options, error);
    }
    result
}

fn deploy_with(options: &Options) -> Result<(), String> {
    validate_target(&options.target)?;
    if let Some(key) = &options.signing_key {
        validate_key(key)?;
    }
    let roots = Roots::create()?;
    let system = build(&options, &roots.0.join("system"))?;
    if let Some(command) = &options.sign_command {
        crate::closure_signing::sign(
            &system,
            &roots.0,
            command,
            &options.sign_args,
            &options.reuse_signature_keys,
        )?;
    } else {
        let mut signing = Command::new("nix");
        signing.args([
            "--extra-experimental-features",
            "nix-command",
            "store",
            "sign",
            "--recursive",
            "--key-file",
        ]);
        if let Some(key) = &options.signing_key {
            run(signing.arg(key).arg(&system), "signing closure")?;
        } else {
            let mut provider =
                Command::new(options.key_command.as_ref().ok_or("missing key provider")?)
                    .args(&options.key_args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .managed_spawn()
                    .map_err(|e| e.to_string())?;
            let input = provider
                .stdout
                .take()
                .ok_or("missing key provider output")?;
            let signed = signing
                .arg("/proc/self/fd/0")
                .arg(&system)
                .stdin(Stdio::from(input))
                .managed_status()
                .map_err(|e| e.to_string());
            let provided = provider.wait().map_err(|e| e.to_string())?;
            if !provided.success() || !signed?.success() {
                return Err("signing closure with key provider failed".into());
            }
        }
    }
    // The one login of this update is approved before it connects.
    options.login_approval.before_connecting()?;
    let transport = Transport::connect(&options)?;
    let store = format!("{}?max-connections=1", store_uri(&options.target)?);
    let progress = crate::progress::Reporter::new(
        options.progress_command.clone(),
        options.progress_args.clone(),
    );
    if committed_system(&transport).as_deref() == Some(system.as_path()) {
        // An earlier run committed this system, and its secret deployment
        // may have failed: resume with that step alone.
        progress.report(
            "resume",
            format!(
                "{} already runs {}; skipping the switch and deploying only the secrets",
                options.target,
                system.display()
            ),
            None,
        );
        secrets_only(&mut || activation_callback(options), &system)?;
    } else {
        copy_closure(&system, &store, &transport, &progress)?;
        apply(&options, &system, &transport, &progress)?;
    }
    if let Some(command) = &options.post_command {
        run(
            Command::new(command).args(&options.post_args),
            "post-update operation",
        )?;
    }
    Ok(())
}

fn copy_closure(
    system: &Path,
    store: &str,
    transport: &Transport,
    progress: &crate::progress::Reporter,
) -> Result<(), String> {
    progress.report("upload", "uploading the closure", Some(0));
    crate::progress::copy(
        Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "copy",
                "--to",
            ])
            .env("NIX_SSHOPTS", transport.nix_options())
            .arg(store)
            .arg(system),
        "copying closure",
        progress,
    )?;
    progress.report("upload", "uploading the closure signatures", Some(100));
    // Copy skips paths that are already valid on the destination. Those paths
    // still need the operator's signatures, including after a fresh install.
    run(
        Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "store",
                "copy-sigs",
                "--substituter",
                "auto",
                "--store",
            ])
            .env("NIX_SSHOPTS", transport.nix_options())
            .arg(store)
            .arg("--recursive")
            .arg(system),
        "copying closure signatures",
    )?;
    Ok(())
}

struct Roots(PathBuf);
impl Roots {
    fn create() -> Result<Self, String> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let path = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(format!(
                "system-update-roots-{}-{stamp}",
                std::process::id()
            ));
        fs::create_dir(&path).map_err(|e| e.to_string())?;
        let roots = Self(path);
        fs::set_permissions(&roots.0, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        eprintln!(
            "Retaining registered GC roots in {} until update completion",
            roots.0.display()
        );
        Ok(roots)
    }
}
impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Options that add to a list; any other given twice is refused.
const REPEATABLE: &[&str] = &[
    "--key-arg", "--sign-arg", "--ssh-arg", "--activation-arg", "--post-arg", "--failure-arg",
    "--warning-arg", "--progress-arg", "--reuse-signatures-by", "--login-approval-arg",
];

fn parse(args: &[String]) -> Result<Options, String> {
    let mut target = None;
    let mut installable = None;
    let mut signing_key = None;
    let mut key_command = None;
    let mut key_args = Vec::new();
    let mut sign_command = None;
    let mut sign_args = Vec::new();
    let mut impure = false;
    let mut activation_command = None;
    let mut activation_args = Vec::new();
    let mut post_command = None;
    let mut post_args = Vec::new();
    let mut ssh_args = Vec::new();
    let mut failure_command = None;
    let mut failure_args = Vec::new();
    let mut warning_command = None;
    let mut warning_args = Vec::new();
    let mut progress_command = None;
    let mut progress_args = Vec::new();
    let mut reuse_signature_keys = Vec::new();
    let mut login_approval = crate::login_approval::LoginApproval::default();
    let mut once = crate::options::Once::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        once.take(arg, REPEATABLE)?;
        if login_approval.parse(arg, &mut iter)? {
            continue;
        }
        match arg.as_str() {
            "--target" => target = iter.next().cloned(),
            "--installable" => installable = iter.next().cloned(),
            "--signing-key" => signing_key = iter.next().map(PathBuf::from),
            "--key-command" => {
                key_command = Some(PathBuf::from(iter.next().ok_or("missing key command")?))
            }
            "--key-arg" => key_args.push(iter.next().ok_or("missing key argument")?.clone()),
            "--sign-command" => {
                sign_command = Some(PathBuf::from(iter.next().ok_or("missing sign command")?))
            }
            "--sign-arg" => sign_args.push(iter.next().ok_or("missing sign argument")?.clone()),
            "--impure" => impure = true,
            "--ssh-arg" => ssh_args.push(iter.next().ok_or("missing SSH argument")?.clone()),
            "--activation-command" => {
                activation_command = Some(PathBuf::from(
                    iter.next().ok_or("missing activation command")?,
                ));
            }
            "--activation-arg" => {
                activation_args.push(iter.next().ok_or("missing activation argument")?.clone())
            }
            "--post-command" => {
                post_command = Some(PathBuf::from(
                    iter.next().ok_or("missing post-update command")?,
                ))
            }
            "--post-arg" => {
                post_args.push(iter.next().ok_or("missing post-update argument")?.clone())
            }
            "--failure-command" => {
                failure_command = Some(PathBuf::from(
                    iter.next().ok_or("missing failure command")?,
                ))
            }
            "--failure-arg" => {
                failure_args.push(iter.next().ok_or("missing failure argument")?.clone())
            }
            "--warning-command" => {
                warning_command = Some(PathBuf::from(
                    iter.next().ok_or("missing warning command")?,
                ))
            }
            "--warning-arg" => {
                warning_args.push(iter.next().ok_or("missing warning argument")?.clone())
            }
            "--progress-command" => {
                progress_command = Some(PathBuf::from(
                    iter.next().ok_or("missing progress command")?,
                ))
            }
            "--progress-arg" => {
                progress_args.push(iter.next().ok_or("missing progress argument")?.clone())
            }
            "--reuse-signatures-by" => reuse_signature_keys
                .push(iter.next().ok_or("missing signature key")?.clone()),
            _ => return Err(format!("unknown deploy argument: {arg}")),
        }
    }
    login_approval.validate()?;
    if !activation_args.is_empty() && activation_command.is_none() {
        return Err("activation arguments require --activation-command".into());
    }
    if !warning_args.is_empty() && warning_command.is_none() {
        return Err("warning arguments require --warning-command".into());
    }
    if !progress_args.is_empty() && progress_command.is_none() {
        return Err("progress arguments require --progress-command".into());
    }
    if !reuse_signature_keys.is_empty() && sign_command.is_none() {
        return Err("--reuse-signatures-by requires --sign-command".into());
    }
    if !failure_args.is_empty() && failure_command.is_none() {
        return Err("failure arguments require --failure-command".into());
    }
    if !post_args.is_empty() && post_command.is_none() {
        return Err("post-update arguments require --post-command".into());
    }
    if [
        signing_key.is_some(),
        key_command.is_some(),
        sign_command.is_some(),
    ]
    .into_iter()
    .filter(|v| *v)
    .count()
        != 1
    {
        return Err("supply exactly one signing key, key command or external signer".into());
    }
    if !key_args.is_empty() && key_command.is_none() {
        return Err("key arguments require --key-command".into());
    }
    if !sign_args.is_empty() && sign_command.is_none() {
        return Err("sign arguments require --sign-command".into());
    }
    Ok(Options {
        target: target.ok_or("missing --target")?,
        installable: installable.ok_or("missing --installable")?,
        signing_key,
        key_command,
        key_args,
        sign_command,
        sign_args,
        impure,
        activation_command,
        activation_args,
        post_command,
        post_args,
        ssh_args,
        login_approval,
        failure_command,
        failure_args,
        warning_command,
        warning_args,
        progress_command,
        progress_args,
        reuse_signature_keys,
    })
}

fn validate_target(target: &str) -> Result<(), String> {
    if target.starts_with('-')
        || target.matches('@').count() != 1
        || target.chars().any(char::is_whitespace)
    {
        return Err("invalid SSH target".into());
    }
    Ok(())
}

fn validate_key(path: &Path) -> Result<(), String> {
    if path.starts_with("/nix/store") || !fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Err("signing key must be a file outside /nix/store".into());
    }
    Ok(())
}

fn build(options: &Options, root: &Path) -> Result<PathBuf, String> {
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--out-link",
        ])
        .arg(root)
        .arg("--print-out-paths");

    if options.impure {
        command.arg("--impure");
    }
    let output = command
        .arg(&options.installable)
        .managed_output_inherit_stderr()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("building system failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "non-UTF-8 build output")?;
    let mut lines = text.lines();
    let path = lines.next().ok_or("build returned no system path")?;
    if lines.next().is_some() || !path.starts_with("/nix/store/") {
        return Err("build returned an invalid system path".into());
    }
    Ok(PathBuf::from(path))
}

fn store_uri(target: &str) -> Result<String, String> {
    let (user, host) = target.split_once('@').ok_or("invalid SSH target")?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into()
    };
    Ok(format!("ssh-ng://{user}@{host}"))
}

// Killing or interrupting the local client must reap its SSH child. A remote
// activation already in progress continues under the root broker, which
// finishes it or rolls it back by itself.
struct ApplyChild(crate::cancellation::ManagedChild);
impl Drop for ApplyChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How long the broker may stay silent while no local step runs. Current
/// brokers send keepalives; older ones are silent until their verdict.
const SILENCE_LIMIT: Duration = Duration::from_secs(600);

fn apply(
    options: &Options,
    system: &Path,
    transport: &Transport,
    progress: &crate::progress::Reporter,
) -> Result<(), String> {
    let target = &options.target;
    let mut child = ApplyChild(
        Command::new("ssh")
            .args(transport.channel_args())
            .args(["--", target, "apply"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .managed_spawn()
            .map_err(|error| error.to_string())?,
    );
    child
        .0
        .stdin
        .take()
        .ok_or("missing SSH stdin")?
        .write_all(protocol::request(system).as_bytes())
        .map_err(|e| e.to_string())?;
    let lines = read_lines(child.0.stdout.take().ok_or("missing SSH stdout")?);
    follow(
        &lines,
        system,
        &mut || activation_callback(options),
        &mut |message| report_failure(options, message),
        &mut |message| report_warning(options, message),
        &mut |stage| progress.stage(stage),
        SILENCE_LIMIT,
    )?;
    let status = child.0.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("remote switch failed or returned an invalid response".into());
    }
    println!("switched {} to {}", target, system.display());
    Ok(())
}

/// Response lines of the broker, read off the SSH channel as they arrive.
fn read_lines(mut stream: impl Read + Send + 'static) -> mpsc::Receiver<Result<String, String>> {
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            let line = protocol::read_control_line(&mut stream);
            let last = line.as_ref().map_or(true, |line| {
                protocol::SwitchLine::parse(line).map_or(true, |parsed| parsed.is_final())
            });
            if last {
                let line = line.and_then(|line| {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(0) => Ok(line),
                        _ => Err("trailing remote switch response".into()),
                    }
                });
                let _ = sender.send(line);
                return;
            }
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    lines
}

/// A local step that runs while the host activates.
trait Running {
    /// `Some(success)` once it ended.
    fn poll(&mut self) -> Result<Option<bool>, String>;
}

struct CallbackChild(crate::cancellation::ManagedChild);
impl Running for CallbackChild {
    fn poll(&mut self) -> Result<Option<bool>, String> {
        Ok(self.0.try_wait().map_err(|e| e.to_string())?.map(|status| status.success()))
    }
}

/// Follows the broker's response to its verdict. The activation callback
/// (the secret deployment) starts when the new system is installed, because
/// its services may wait for it; it is stopped as soon as the host reports a
/// failure and never started after one. Only `OK` with a successful callback
/// is success.
fn follow(
    lines: &mpsc::Receiver<Result<String, String>>,
    system: &Path,
    start: &mut dyn FnMut() -> Result<Option<Box<dyn Running>>, String>,
    report: &mut dyn FnMut(&str),
    warn: &mut dyn FnMut(&str),
    stage: &mut dyn FnMut(protocol::Stage),
    silence_limit: Duration,
) -> Result<(), String> {
    use protocol::SwitchLine;
    let mut warnings: Vec<String> = Vec::new();
    let mut activated = false;
    let mut failed = false;
    let mut running: Option<Box<dyn Running>> = None;
    let mut callback: Option<Result<(), String>> = None;
    let mut last_stage = None;
    let mut last = Instant::now();
    let callback_failed = || Err("configuration activation operation failed".to_owned());
    loop {
        if let Some(step) = running.as_mut() {
            if let Some(success) = step.poll()? {
                running = None;
                callback = Some(if success { Ok(()) } else { callback_failed() });
                last = Instant::now();
                if !success {
                    report("the activation callback failed while the host activates; waiting for the host");
                }
            }
        }
        let line = match lines.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if running.is_none() && last.elapsed() >= silence_limit {
                    return Err("remote activation produced no progress for 10 minutes; an older broker may need secrets deployed before this upgrade".into());
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("the response ended".into()),
        };
        last = Instant::now();
        let line = match line.and_then(|line| SwitchLine::parse(&line)) {
            Ok(line) => line,
            Err(error) => {
                // Dropping a running callback stops it.
                return Err(format!(
                    "lost the update connection before the host's verdict ({error}); \
                     the host finishes the update or rolls it back by itself"
                ));
            }
        };
        let entered = line.stage();
        match line {
            SwitchLine::Activated(path) if path == system && !activated => {
                activated = true;
                if !failed {
                    running = start()?;
                    if running.is_none() {
                        callback = Some(Ok(()));
                    }
                }
            }
            SwitchLine::Failed(reason) if !failed => {
                failed = true;
                running = None;
                report(&format!("activation failed, the host is rolling back: {reason}"));
            }
            SwitchLine::Waiting(_) => {
                // The login helper and the broker both verify.
                if let Some(entered) = entered.filter(|entered| last_stage != Some(*entered)) {
                    last_stage = Some(entered);
                    stage(entered);
                }
            }
            SwitchLine::Warning(text) => {
                eprintln!("nix-update-remote: warning: {text}");
                warnings.push(text);
            }
            SwitchLine::Ok(path) if path == system && !failed => {
                if !activated {
                    // Legacy brokers emit only the final receipt.
                    running = start()?;
                    callback = Some(Ok(()));
                }
                while let Some(step) = running.as_mut() {
                    if let Some(success) = step.poll()? {
                        running = None;
                        callback = Some(if success { Ok(()) } else { callback_failed() });
                    } else {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                if !warnings.is_empty() {
                    warn(&format!("updated with warnings: {}", warnings.join("; ")));
                }
                // The host committed: only the secrets are missing.
                return callback
                    .unwrap_or_else(callback_failed)
                    .map_err(|_| secrets_not_deployed(system));
            }
            verdict if verdict.is_final() && verdict.failure().is_some() => {
                return Err(verdict.failure().unwrap());
            }
            _ => return Err("invalid or duplicate activation progress event".into()),
        }
    }
}
struct Transport {
    directory: PathBuf,
    master: Option<crate::cancellation::ManagedChild>,
    target: String,
    args: Vec<String>,
}
impl Transport {
    fn connect(options: &Options) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("nur-{}-{stamp}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|e| e.to_string())?;
        let mut transport = Self {
            args: vec![
                "-o".into(),
                format!("ControlPath={}", directory.join("ssh").display()),
                "-o".into(),
                "ControlMaster=no".into(),
                "-o".into(),
                "ControlPersist=no".into(),
                "-o".into(),
                "ProxyCommand=false".into(),
            ],
            directory,
            master: None,
            target: options.target.clone(),
        };
        let mut command = Command::new("ssh");
        command
            .args([
                "-M",
                "-N",
                "-T",
                "-o",
                "ControlMaster=yes",
                "-o",
                "ControlPersist=no",
                "-o",
                "ForkAfterAuthentication=no",
                "-o",
                "PermitLocalCommand=no",
            ])
            .args(["-S"])
            .arg(transport.directory.join("ssh"))
            .args(&options.ssh_args)
            .args(["--", &options.target])
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        transport.master = Some(command.managed_spawn().map_err(|e| e.to_string())?);
        loop {
            if transport
                .master
                .as_mut()
                .unwrap()
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err(
                    "operation SSH connection failed before authentication completed".into(),
                );
            }
            let status = Command::new("ssh")
                .args(transport.channel_args())
                .args(["-O", "check", "--", &transport.target])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .managed_status()
                .map_err(|e| e.to_string())?;
            if status.success() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(transport)
    }
    fn channel_args(&self) -> &[String] {
        &self.args
    }
    fn nix_options(&self) -> String {
        self.args
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\"'\"'")))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(mut child) = self.master.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The system the host runs and has committed, from its login helper; `None`
/// when it is not committed, or the helper predates the question.
fn committed_system(transport: &Transport) -> Option<PathBuf> {
    let output = Command::new("ssh")
        .args(transport.channel_args())
        .args(["--", &transport.target, "committed-system"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .managed_output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let path = text.strip_suffix('\n')?;
    (output.status.success() && path.starts_with("/nix/store/") && !path.contains('\n'))
        .then(|| PathBuf::from(path))
}

/// What the operator must read when the host committed `system` but the
/// secret deployment did not finish.
fn secrets_not_deployed(system: &Path) -> String {
    format!(
        "update committed, secrets NOT deployed: the host now runs {}, but its secret deployment failed. \
         Run the same update again: it skips the switch and deploys only the secrets",
        system.display()
    )
}

/// Runs the secret deployment for a host that already runs `system`.
fn secrets_only(
    start: &mut dyn FnMut() -> Result<Option<Box<dyn Running>>, String>,
    system: &Path,
) -> Result<(), String> {
    let Some(mut step) = start()? else { return Ok(()) };
    loop {
        match step.poll()? {
            Some(true) => return Ok(()),
            Some(false) => return Err(secrets_not_deployed(system)),
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn activation_callback(options: &Options) -> Result<Option<Box<dyn Running>>, String> {
    let Some(command) = &options.activation_command else {
        return Ok(None);
    };
    let child = Command::new(command)
        .args(&options.activation_args)
        .stdin(Stdio::null())
        .managed_spawn()
        .map_err(|e| format!("configuration activation operation: {e}"))?;
    Ok(Some(Box::new(CallbackChild(child))))
}

/// Tells the operator what an update that succeeded left broken.
fn report_warning(options: &Options, message: &str) {
    eprintln!("nix-update-remote: {message}");
    if let Some(command) = &options.warning_command {
        report_with(command, &options.warning_args, message);
    }
}

/// Tells the operator about a failure as soon as it is known, through the
/// configured reporter (such as a procedure step in the operator's TUI).
/// Reporting never changes the outcome.
fn report_failure(options: &Options, message: &str) {
    eprintln!("nix-update-remote: {message}");
    if let Some(command) = &options.failure_command {
        report_with(command, &options.failure_args, message);
    }
}

pub fn report_with(command: &Path, args: &[String], message: &str) {
    let status = Command::new(command)
        .args(args)
        .arg(protocol::one_line(message))
        .stdin(Stdio::null())
        .managed_status();
    if !status.is_ok_and(|status| status.success()) {
        eprintln!("nix-update-remote: the failure reporter did not confirm the report");
    }
}

fn run(command: &mut Command, action: &str) -> Result<(), String> {
    command.stdin(Stdio::null());
    command
        .managed_status()
        .map_err(|e| e.to_string())
        .and_then(|status| {
            status
                .success()
                .then_some(())
                .ok_or_else(|| format!("{action} failed"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the normal integration SSH receiver"]
    fn real_nix_transport_lost_master_never_reauthenticates() {
        let target = std::env::var("NIX_UPDATE_TRANSPORT_TEST_TARGET").unwrap();
        let system = PathBuf::from(std::env::var("NIX_UPDATE_TRANSPORT_TEST_SYSTEM").unwrap());
        let args: Vec<String> =
            serde_json::from_str(&std::env::var("NIX_UPDATE_TRANSPORT_TEST_ARGS").unwrap())
                .unwrap();
        let mut cli = vec![
            "--target".into(),
            target.clone(),
            "--installable".into(),
            "fixture".into(),
            "--key-command".into(),
            "/unused-provider".into(),
        ];
        for arg in args {
            cli.extend(["--ssh-arg".into(), arg]);
        }
        let options = parse(&cli).unwrap();
        let mut transport = Transport::connect(&options).unwrap();
        let directory = transport.directory.clone();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let store = format!("{}?max-connections=1", store_uri(&target).unwrap());
        copy_closure(&system, &store, &transport, &crate::progress::Reporter::new(None, Vec::new())).unwrap();
        let mut master = transport.master.take().unwrap();
        master.kill().unwrap();
        master.wait().unwrap();
        assert!(
            copy_closure(&system, &store, &transport, &crate::progress::Reporter::new(None, Vec::new())).is_err(),
            "lost master silently opened another connection"
        );
        let status = Command::new("ssh")
            .args(transport.channel_args())
            .args(["--", &target, "apply"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "apply reconnected after master loss");
        drop(transport);
        assert!(!directory.exists());
    }

    #[test]
    fn activation_callback_precedes_final_receipt_on_same_stream() {
        let (mut server, client) = std::os::unix::net::UnixStream::pair().unwrap();
        let lines = read_lines(client);
        let (notice, confirmed) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            server.write_all(b"ACTIVATED /nix/store/test-system\n").unwrap();
            confirmed.recv_timeout(Duration::from_secs(2)).unwrap();
            server.write_all(b"OK /nix/store/test-system\n").unwrap();
        });
        let probe = Probe::default();
        let mut start = probe.starter(Some(true));
        let result = follow(
            &lines,
            Path::new("/nix/store/test-system"),
            &mut || {
                notice.send(()).unwrap();
                start()
            },
            &mut |_| panic!("nothing failed"),
            &mut |_| panic!("no warning"),
            &mut |_| {},
            SILENCE_LIMIT,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        writer.join().unwrap();
    }

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A callback that ends with `outcome` (or never) and records whether it
    /// was stopped before it ended.
    #[derive(Clone, Default)]
    struct Probe {
        started: Arc<AtomicUsize>,
        stopped: Arc<AtomicBool>,
    }
    struct FakeStep(Probe, Option<bool>, bool, Instant);
    impl Running for FakeStep {
        fn poll(&mut self) -> Result<Option<bool>, String> {
            if Instant::now() < self.3 {
                return Ok(None);
            }
            self.2 = self.1.is_some();
            Ok(self.1)
        }
    }
    impl Drop for FakeStep {
        fn drop(&mut self) {
            if !self.2 {
                self.0.stopped.store(true, Ordering::SeqCst);
            }
        }
    }
    impl Probe {
        fn starter(&self, outcome: Option<bool>) -> impl FnMut() -> Result<Option<Box<dyn Running>>, String> {
            self.delayed(outcome, Duration::ZERO)
        }
        fn delayed(&self, outcome: Option<bool>, delay: Duration) -> impl FnMut() -> Result<Option<Box<dyn Running>>, String> {
            let probe = self.clone();
            move || {
                probe.started.fetch_add(1, Ordering::SeqCst);
                Ok(Some(Box::new(FakeStep(probe.clone(), outcome, false, Instant::now() + delay)) as Box<dyn Running>))
            }
        }
    }

    fn feed(lines: &[&str], end: bool) -> mpsc::Receiver<Result<String, String>> {
        let (sender, receiver) = mpsc::channel();
        for line in lines {
            sender.send(Ok(line.to_string())).unwrap();
        }
        if end {
            sender.send(Err("reading control header: failed to fill whole buffer".into())).unwrap();
        } else {
            std::mem::forget(sender);
        }
        receiver
    }

    fn drive(lines: &[&str], end: bool, outcome: Option<bool>) -> (Result<(), String>, Probe, Vec<String>) {
        let probe = Probe::default();
        let reports = std::cell::RefCell::new(Vec::new());
        let result = follow(
            &feed(lines, end),
            Path::new("/nix/store/test-system"),
            &mut probe.starter(outcome),
            &mut |message| reports.borrow_mut().push(message.to_owned()),
            &mut |message| reports.borrow_mut().push(format!("WARN {message}")),
            &mut |stage| reports.borrow_mut().push(format!("STAGE {}", stage.word())),
            Duration::from_millis(300),
        );
        (result, probe, reports.into_inner())
    }

    #[test]
    fn each_host_stage_reaches_the_operator_once_as_it_starts() {
        let (result, _, reports) = drive(
            &[
                "WAITING stage verifying",
                "WAITING stage verifying",
                "WAITING stage activating",
                "WAITING switch-to-configuration test",
                "ACTIVATED /nix/store/test-system",
                "WAITING stage health-gate",
                "WAITING checking the system health",
                "WAITING stage committing",
                "OK /nix/store/test-system",
            ],
            false,
            Some(true),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            reports,
            ["STAGE verifying", "STAGE activating", "STAGE health-gate", "STAGE committing"]
        );
        let (result, _, reports) = drive(
            &[
                "WAITING stage activating",
                "FAILED status 4",
                "WAITING stage rolling-back",
                "ROLLED-BACK status 4; restored",
            ],
            false,
            None,
        );
        assert!(result.is_err());
        assert_eq!(reports[0], "STAGE activating");
        assert!(reports[1].contains("rolling back: status 4"), "{reports:?}");
        assert_eq!(reports[2], "STAGE rolling-back");
    }

    #[test]
    fn pre_existing_failures_commit_and_reach_the_operator_as_warnings() {
        let (result, probe, reports) = drive(
            &[
                "ACTIVATED /nix/store/test-system",
                "WARNING switch-to-configuration test exited with status 4",
                "WARNING old.service was already failed before the update and still is",
                "OK /nix/store/test-system",
            ],
            false,
            Some(true),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(probe.started.load(Ordering::SeqCst), 1, "the secret step runs after a warning");
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert!(reports[0].starts_with("WARN updated with warnings: "), "{reports:?}");
        assert!(reports[0].contains("old.service was already failed"), "{reports:?}");
    }

    #[test]
    fn the_secret_step_stops_when_the_failure_arrives_not_with_the_verdict() {
        let (sender, lines) = mpsc::channel();
        let probe = Probe::default();
        let watched = probe.clone();
        let follower = std::thread::spawn(move || {
            follow(
                &lines,
                Path::new("/nix/store/test-system"),
                &mut watched.starter(None),
                &mut |_| {},
                &mut |_| {},
                &mut |_| {},
                SILENCE_LIMIT,
            )
        });
        sender.send(Ok("ACTIVATED /nix/store/test-system".to_owned())).unwrap();
        sender.send(Ok("FAILED status 4".to_owned())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !probe.stopped.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(probe.stopped.load(Ordering::SeqCst), "the secret step outlived the failure");
        sender.send(Ok("ROLLED-BACK status 4".to_owned())).unwrap();
        assert!(follower.join().unwrap().is_err());
    }

    #[test]
    fn host_failure_stops_the_secret_step_and_reports_before_the_verdict() {
        let (result, probe, reports) = drive(
            &[
                "ACTIVATED /nix/store/test-system",
                "FAILED switch-to-configuration test exited with status 4",
                "WAITING switch-to-configuration test",
                "ROLLED-BACK status 4; previous system /nix/store/old restored and verified",
            ],
            false,
            None,
        );
        let error = result.unwrap_err();
        assert!(error.contains("rolled back"), "{error}");
        assert!(error.contains("restored and verified"), "{error}");
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        assert!(probe.stopped.load(Ordering::SeqCst), "the secret step kept running");
        assert_eq!(reports.len(), 1);
        assert!(reports[0].contains("rolling back: switch-to-configuration test exited with status 4"));
    }

    #[test]
    fn rejected_or_failed_updates_never_start_the_secret_step() {
        for lines in [
            &["REJECTED closure lacks a signature by a trusted update key"][..],
            &["ERR update rejected"][..],
            &["FAILED x", "ACTIVATED /nix/store/test-system", "ROLLBACK-FAILED x; sshd is not listening"][..],
        ] {
            let (result, probe, _) = drive(lines, false, Some(true));
            assert!(result.is_err(), "{lines:?}");
            assert_eq!(probe.started.load(Ordering::SeqCst), 0, "{lines:?}");
        }
        let (result, _, _) = drive(&["REJECTED bad signature"], false, None);
        assert!(result.unwrap_err().contains("host is unchanged: bad signature"));
        let (result, _, _) = drive(&["FAILED x", "ACTIVATED /nix/store/test-system", "ROLLBACK-FAILED y"], false, None);
        assert!(result.unwrap_err().contains("ROLLING BACK FAILED"));
    }

    #[test]
    fn lost_connection_mid_switch_stops_the_secret_step_and_fails() {
        let (result, probe, _) = drive(&["ACTIVATED /nix/store/test-system"], true, None);
        let error = result.unwrap_err();
        assert!(error.contains("lost the update connection"), "{error}");
        assert!(error.contains("rolls it back by itself"), "{error}");
        assert!(probe.stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn success_needs_the_verdict_and_the_secret_step() {
        let (result, probe, _) = drive(&["ACTIVATED /nix/store/test-system", "OK /nix/store/test-system"], false, Some(true));
        assert_eq!(result, Ok(()));
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        let (result, _, reports) = drive(&["ACTIVATED /nix/store/test-system", "OK /nix/store/test-system"], false, Some(false));
        let error = result.unwrap_err();
        // The operator must see that the host changed and what is missing.
        assert!(error.contains("update committed, secrets NOT deployed"), "{error}");
        assert!(error.contains("/nix/store/test-system"), "{error}");
        assert!(error.contains("deploys only the secrets"), "{error}");
        assert_eq!(reports.len(), 1, "a failed secret step is reported at once");
        // Legacy brokers send only their receipt; the callback runs once.
        let (result, probe, _) = drive(&["OK /nix/store/test-system"], false, Some(true));
        assert_eq!(result, Ok(()));
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn resuming_a_committed_host_runs_only_the_secret_step() {
        let system = Path::new("/nix/store/test-system");
        let probe = Probe::default();
        assert_eq!(secrets_only(&mut probe.starter(Some(true)), system), Ok(()));
        assert_eq!(probe.started.load(Ordering::SeqCst), 1);
        let error = secrets_only(&mut probe.starter(Some(false)), system).unwrap_err();
        assert!(error.contains("update committed, secrets NOT deployed"), "{error}");
        // Without a secret step there is nothing left to do.
        assert_eq!(secrets_only(&mut || Ok(None), system), Ok(()));
    }

    #[test]
    fn invalid_progress_is_rejected_and_silence_times_out() {
        for lines in [
            &["ACTIVATED /nix/store/wrong"][..],
            &["ACTIVATED /nix/store/test-system", "ACTIVATED /nix/store/test-system"][..],
            &["FAILED a", "FAILED b"][..],
            &["FAILED a", "OK /nix/store/test-system"][..],
            &["OK /nix/store/wrong"][..],
            &["SOMETHING"][..],
        ] {
            assert!(drive(lines, false, Some(true)).0.is_err(), "{lines:?}");
        }
        let (result, _, _) = drive(&[], false, None);
        assert!(result.unwrap_err().contains("no progress"));
        // A running secret step is not silence: the deployment may wait for
        // its operator longer than the limit.
        let (sender, lines) = mpsc::channel();
        sender.send(Ok("ACTIVATED /nix/store/test-system".to_owned())).unwrap();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(700));
            sender.send(Ok("OK /nix/store/test-system".to_owned())).unwrap();
        });
        let probe = Probe::default();
        let result = follow(
            &lines,
            Path::new("/nix/store/test-system"),
            &mut probe.delayed(Some(true), Duration::from_millis(600)),
            &mut |_| {},
            &mut |_| {},
            &mut |_| {},
            Duration::from_millis(300),
        );
        assert_eq!(result, Ok(()));
        late.join().unwrap();
    }

    #[test]
    fn external_native_signing_is_exclusive_and_arguments_require_command() {
        let base = ["--target", "update@example.org", "--installable", ".#host"];
        let args = |extra: &[&str]| {
            base.iter()
                .chain(extra.iter())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        };
        assert!(
            parse(&args(&[
                "--sign-command",
                "external-signer",
                "--sign-arg",
                "reason"
            ]))
            .is_ok()
        );
        assert!(
            parse(&args(&[
                "--sign-command",
                "external-signer",
                "--signing-key",
                "/private"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "--sign-command",
                "external-signer",
                "--key-command",
                "provider"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "--signing-key",
                "/private",
                "--sign-arg",
                "orphan"
            ]))
            .is_err()
        );
    }

    #[test]
    fn a_backend_option_given_twice_is_refused() {
        let base = ["--target", "update@example.org", "--installable", ".#host", "--sign-command", "/s", "--sign-arg", "a", "--sign-arg", "b"];
        let args = |extra: &[&str]| base.iter().chain(extra).map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse(&args(&["--ssh-arg", "-v", "--ssh-arg", "-v"])).is_ok(), "list options add up");
        for extra in [
            &["--target", "update@evil.example"][..],
            &["--installable", "path:/tmp/evil#host"],
            &["--sign-command", "/evil"],
            &["--impure", "--impure"],
            &["--activation-command", "/a", "--activation-command", "/b"],
            &["--failure-command", "/a", "--failure-command", "/b"],
            &["--login-approval-command", "/a", "--login-approval-command", "/b"],
        ] {
            assert!(parse(&args(extra)).err().unwrap().contains("more than once"), "{extra:?}");
        }
    }

    #[test]
    fn target_requires_one_user_and_supports_ipv6() {
        assert!(validate_target("update@example.org").is_ok());
        assert_eq!(
            store_uri("update@2001:db8::1").unwrap(),
            "ssh-ng://update@[2001:db8::1]"
        );
        assert!(validate_target("-oProxyCommand=x@example.org").is_err());
        assert!(validate_target("a@b@c").is_err());
        assert!(validate_target("update@example.org command").is_err());
    }
}
