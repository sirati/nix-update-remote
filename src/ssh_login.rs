use crate::{protocol, verify};
use std::env;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command] if command == "current-system" => {
            let path =
                std::fs::read_link("/run/current-system").map_err(|error| error.to_string())?;
            if !path.starts_with("/nix/store/") {
                return Err("current system is not canonical in the Nix store".into());
            }
            println!("{}", path.display());
            Ok(())
        }
        [command]
            if env::var("NIX_UPDATE_REMOTE_MODE").as_deref() != Ok("artifact")
                && (command == "nix-daemon --stdio"
                    || command == "/run/current-system/sw/bin/nix-daemon --stdio") =>
        {
            nix_daemon()
        }
        [command]
            if command == "apply"
                && env::var("NIX_UPDATE_REMOTE_MODE").as_deref() != Ok("artifact") =>
        {
            proxy_apply()
        }
        [command]
            if command == "nmbl-erofs-receive"
                && env::var("NIX_UPDATE_REMOTE_MODE").as_deref() == Ok("artifact") =>
        {
            proxy_artifact()
        }
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
    relay_apply_response(&mut socket, &mut io::stdout(), &system)
}

fn relay_apply_response(
    reader: &mut impl Read,
    writer: &mut impl Write,
    system: &Path,
) -> Result<(), String> {
    let mut activated = false;
    for _ in 0..2 {
        let line = protocol::read_control_line(reader)?;
        let progress = line == format!("ACTIVATED {}", system.display());
        let success = line == format!("OK {}", system.display());
        let failure = line == "ERR update rejected";
        if progress && !activated {
            activated = true;
        } else if !success && !failure {
            return Err("invalid broker activation response".into());
        }
        writeln!(writer, "{line}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        if success || failure {
            let mut trailing = [0];
            if reader.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
                return Err("trailing broker response".into());
            }
            return if success {
                Ok(())
            } else {
                Err("update daemon rejected the request".into())
            };
        }
    }
    Err("missing final broker activation response".into())
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

fn proxy_artifact() -> Result<(), String> {
    let mut socket = UnixStream::connect(protocol::SOCKET).map_err(|error| error.to_string())?;
    socket
        .write_all(b"NIX_UPDATE_REMOTE_1\nARTIFACT\n")
        .map_err(|error| error.to_string())?;
    io::copy(&mut io::stdin(), &mut socket).map_err(|error| error.to_string())?;
    socket
        .shutdown(Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    socket
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    io::stdout()
        .write_all(&response)
        .map_err(|error| error.to_string())?;
    response
        .starts_with(b"OK ")
        .then_some(())
        .ok_or("update daemon rejected the artifact".into())
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    #[test]
    fn login_proxy_flushes_progress_before_broker_completion() {
        let (mut broker, mut input) = UnixStream::pair().unwrap();
        let (mut output, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let proxy = std::thread::spawn(move || {
            relay_apply_response(&mut input, &mut output, Path::new("/nix/store/test-system"))
        });
        broker
            .write_all(b"ACTIVATED /nix/store/test-system\n")
            .unwrap();
        assert_eq!(
            protocol::read_control_line(&mut client).unwrap(),
            "ACTIVATED /nix/store/test-system"
        );
        broker.write_all(b"OK /nix/store/test-system\n").unwrap();
        broker.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            protocol::read_control_line(&mut client).unwrap(),
            "OK /nix/store/test-system"
        );
        assert!(proxy.join().unwrap().is_ok());
    }
    #[test]
    fn login_proxy_rejects_duplicate_or_wrong_progress_and_preserves_failure() {
        for bytes in [
            b"ACTIVATED /nix/store/wrong\n".as_slice(),
            b"ACTIVATED /nix/store/test-system\nACTIVATED /nix/store/test-system\n",
            b"ACTIVATED /nix/store/test-system\nERR update rejected\n",
        ] {
            assert!(
                relay_apply_response(
                    &mut &bytes[..],
                    &mut Vec::new(),
                    Path::new("/nix/store/test-system")
                )
                .is_err()
            );
        }
    }
}
