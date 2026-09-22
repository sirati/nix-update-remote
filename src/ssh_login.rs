use crate::{protocol, verify};
use std::env;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command]
            if command == "nix-daemon --stdio"
                || command == "/run/current-system/sw/bin/nix-daemon --stdio" =>
        {
            nix_daemon()
        }
        [command] if command == "apply" => proxy_apply(),
        _ => Err("SSH account accepts only the updater protocol".into()),
    }
}

fn nix_daemon() -> Result<(), String> {
    let status = Command::new("/run/current-system/sw/bin/nix-daemon")
        .arg("--stdio")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| error.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or("Nix daemon protocol failed".into())
}

fn proxy_apply() -> Result<(), String> {
    let mut request = Vec::new();
    io::stdin()
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut request)
        .map_err(|error| error.to_string())?;
    let request_text = std::str::from_utf8(&request).map_err(|_| "request is not UTF-8")?;
    let requested = protocol::parse_request(request_text)?;
    let system = verify::system(&requested)?;
    let (static_keys, runtime_keys) = trust_from_environment()?;
    verify::closure(
        Path::new("/run/current-system/sw/bin/nix"),
        &system,
        &static_keys,
        runtime_keys.as_deref(),
    )?;
    let mut socket = UnixStream::connect(protocol::SOCKET).map_err(|error| error.to_string())?;
    socket
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    socket
        .shutdown(Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    socket
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    io::stdout()
        .write_all(&response)
        .map_err(|error| error.to_string())?;
    response
        .starts_with(b"OK ")
        .then_some(())
        .ok_or("update daemon rejected the request".into())
}

fn trust_from_environment() -> Result<(Vec<String>, Option<std::path::PathBuf>), String> {
    let static_keys = env::var("NIX_UPDATE_REMOTE_STATIC_KEYS")
        .map_err(|_| "missing static trust configuration")?
        .split(',')
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let runtime_keys = env::var_os("NIX_UPDATE_REMOTE_RUNTIME_KEYS").map(std::path::PathBuf::from);
    Ok((static_keys, runtime_keys))
}
