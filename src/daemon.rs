use crate::{protocol, verify};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
}

pub fn run(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    if !rustix::process::geteuid().is_root() {
        return Err("daemon role must run as root".into());
    }
    protocol::remove_stale_socket(&options.socket)?;
    let listener = UnixListener::bind(&options.socket).map_err(|error| error.to_string())?;
    fs::set_permissions(&options.socket, fs::Permissions::from_mode(0o660))
        .map_err(|error| error.to_string())?;
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => handle(stream, &options),
            Err(error) => eprintln!("nix-update-remote: accept failed: {error}"),
        }
    }
    Ok(())
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
    let mut artifact_prepare_args = Vec::new();
    let mut artifact_activate_args = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
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
            _ => return Err(format!("unknown daemon argument: {arg}")),
        }
    }
    if artifact_prepare.is_some() != artifact_activate.is_some() {
        return Err("artifact backend requires prepare and activate executables".into());
    }
    for command in artifact_prepare
        .iter()
        .chain(artifact_activate.iter())
        .chain(reboot_command.iter())
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

fn handle(mut stream: UnixStream, options: &Options) {
    let result = apply_request(&mut stream, options);
    let response = match &result {
        Ok((path, _)) => format!("OK {}\n", path.display()),
        Err(error) => {
            eprintln!("nix-update-remote: rejected update: {error}");
            "ERR update rejected\n".into()
        }
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Write);
    if matches!(result, Ok((_, true))) {
        if let Some(command) = &options.reboot_command {
            if let Err(error) = verify::checked(
                Command::new(command).args(["--no-block", "reboot"]),
                "requesting reboot",
            ) {
                eprintln!("nix-update-remote: {error}");
            }
        }
    }
}

fn apply_request(stream: &mut UnixStream, options: &Options) -> Result<(PathBuf, bool), String> {
    authenticate_peer(stream, options.update_uid)?;
    if protocol::read_control_line(stream)? != protocol::MAGIC {
        return Err("invalid protocol header".into());
    }
    let operation = protocol::read_control_line(stream)?;
    if operation == "ARTIFACT" {
        return apply_artifact(stream, options);
    }
    if operation != "SWITCH" || options.artifact_prepare.is_some() {
        return Err("operation is disabled for this backend".into());
    }
    let mut bytes = Vec::new();
    stream
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    authenticate_peer(stream, options.update_uid)?;
    let tail = String::from_utf8(bytes).map_err(|_| "request is not UTF-8")?;
    let requested = protocol::parse_request(&format!("{}\nSWITCH\n{tail}", protocol::MAGIC))?;
    let resolved = verify::system(&requested)?;
    let switch = resolved.join("bin/switch-to-configuration");
    verify::closure(
        &options.nix,
        &resolved,
        &options.static_keys,
        options.key_file.as_deref(),
    )?;
    record_event(options, &resolved, "before", "pending");
    let activation = (|| {
        verify::checked(
            Command::new(&options.nix_env)
                .args(["--profile"])
                .arg(&options.profile)
                .args(["--set"])
                .arg(&resolved),
            "setting system profile",
        )?;
        verify::checked(Command::new(&switch).arg("switch"), "activating system")?;
        Ok::<(), String>(())
    })();
    let result = if activation.is_ok() {
        "success"
    } else {
        "failure"
    };
    record_event(options, &resolved, "after", result);
    activation?;
    Ok((resolved, false))
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
    let peer = fs::metadata(peer_exe).map_err(|error| error.to_string())?;
    let own = fs::metadata("/proc/self/exe").map_err(|error| error.to_string())?;
    if peer.dev() != own.dev() || peer.ino() != own.ino() {
        return Err("control peer is not this updater binary".into());
    }
    Ok(())
}
