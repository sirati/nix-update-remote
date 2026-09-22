use crate::{protocol, verify};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

struct Options {
    socket: PathBuf,
    nix: PathBuf,
    nix_env: PathBuf,
    profile: PathBuf,
    static_keys: Vec<String>,
    key_file: Option<PathBuf>,
    update_uid: u32,
    hook_uid: Option<u32>,
    hook_gid: Option<u32>,
    before_hooks: Vec<PathBuf>,
    after_hooks: Vec<PathBuf>,
    hook_path: String,
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
    let mut hook_path = "/run/current-system/sw/bin".to_owned();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
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
            "--hook-path" => hook_path = next_value(&mut iter, arg)?,
            _ => return Err(format!("unknown daemon argument: {arg}")),
        }
    }
    if static_keys.is_empty() && key_file.is_none() {
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
        hook_uid,
        hook_gid,
        before_hooks,
        after_hooks,
        hook_path,
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
    let response = match result {
        Ok(path) => format!("OK {}\n", path.display()),
        Err(error) => {
            eprintln!("nix-update-remote: rejected update: {error}");
            "ERR update rejected\n".into()
        }
    };
    let _ = stream.write_all(response.as_bytes());
}

fn apply_request(stream: &mut UnixStream, options: &Options) -> Result<PathBuf, String> {
    authenticate_peer(stream, options.update_uid)?;
    let mut bytes = Vec::new();
    stream
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    authenticate_peer(stream, options.update_uid)?;
    let request = String::from_utf8(bytes).map_err(|_| "request is not UTF-8")?;
    let requested = protocol::parse_request(&request)?;
    let resolved = verify::system(&requested)?;
    let switch = resolved.join("bin/switch-to-configuration");
    verify::closure(
        &options.nix,
        &resolved,
        &options.static_keys,
        options.key_file.as_deref(),
    )?;
    run_hooks(
        &options.before_hooks,
        options,
        &resolved,
        "before",
        "pending",
    )?;
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
    if let Err(error) = run_hooks(&options.after_hooks, options, &resolved, "after", result) {
        eprintln!("nix-update-remote: after-update hook failed: {error}");
    }
    activation?;
    Ok(resolved)
}

fn run_hooks(
    hooks: &[PathBuf],
    options: &Options,
    system: &std::path::Path,
    phase: &str,
    result: &str,
) -> Result<(), String> {
    for hook in hooks {
        let mut command = Command::new(hook);
        command
            .env_clear()
            .env("PATH", &options.hook_path)
            .env("UPDATE_PHASE", phase)
            .env("UPDATE_RESULT", result)
            .env("UPDATE_SYSTEM", system)
            .uid(options.hook_uid.ok_or("hook UID missing")?)
            .gid(options.hook_gid.ok_or("hook GID missing")?);
        verify::checked(
            &mut command,
            &format!("{phase}-update hook {}", hook.display()),
        )?;
    }
    Ok(())
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
