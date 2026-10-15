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
        [command] if command == "committed-system" => {
            let path = committed_system(Path::new("/run/current-system"), Path::new(PROFILE))?;
            println!("{}", path.display());
            Ok(())
        }
        [command] if command == "transaction-phase" => {
            println!("{}", transaction_phase(Path::new(protocol::PHASE_FILE))?);
            Ok(())
        }
        [command] if command == "ping" => {
            println!("{}", ping(Path::new(protocol::SOCKET), RETRY_LIMIT)?);
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

const PROFILE: &str = "/nix/var/nix/profiles/system";

/// The running system, if it is also the one the system profile names: an
/// update to it committed, and none is half done.
fn committed_system(current: &Path, profile: &Path) -> Result<std::path::PathBuf, String> {
    let running = std::fs::canonicalize(current).map_err(|error| format!("{}: {error}", current.display()))?;
    let committed = std::fs::canonicalize(profile).map_err(|error| format!("{}: {error}", profile.display()))?;
    if !running.starts_with("/nix/store/") {
        return Err("current system is not canonical in the Nix store".into());
    }
    if running != committed {
        return Err("the running system is not the committed system profile".into());
    }
    Ok(running)
}

/// The phase of the broker's transaction in progress, `idle` without one.
/// The broker publishes only this word of its root-only journal.
fn transaction_phase(published: &Path) -> Result<&'static str, String> {
    match std::fs::read(published) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok("idle"),
        Err(error) => Err(format!("cannot read the update phase: {error}")),
        Ok(bytes) => match bytes.as_slice() {
            b"activating\n" => Ok("activating"),
            b"committing\n" => Ok("committing"),
            _ => Err("the published update phase is invalid".into()),
        },
    }
}

/// Asks the broker for its version, through the same socket and peer check
/// as an update. A broker that restarts into the current updater, or whose
/// socket is briefly gone between two brokers, is asked again until `limit`
/// passes; a busy broker is waited for.
fn ping(socket: &Path, limit: std::time::Duration) -> Result<String, String> {
    let deadline = std::time::Instant::now() + limit;
    loop {
        // Only reaching the broker is retried; its answer is final.
        let error = match send_apply_request(socket, protocol::ping_request().as_bytes(), limit) {
            Ok((first, mut rest)) => {
                let mut trailing = [0];
                return match rest.read(&mut trailing) {
                    Ok(0) => protocol::parse_pong(&first),
                    _ => Err("trailing broker response".into()),
                };
            }
            Err(error) => error,
        };
        if std::time::Instant::now() >= deadline {
            return Err(format!("cannot reach the update broker: {error}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
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
    let (request, system) = match checked_apply_request() {
        Ok(checked) => checked,
        Err(error) => {
            // The client hears that nothing changed, not that the line died.
            println!("REJECTED {}", protocol::one_line(&error));
            return Err(error);
        }
    };
    let (first, mut socket) = send_apply_request(Path::new(protocol::SOCKET), &request, RETRY_LIMIT)?;
    relay_apply_response(
        &mut io::Cursor::new(format!("{first}\n")).chain(&mut socket),
        &mut io::stdout(),
        &system,
    )
}

/// How long a login waits for a broker that restarts into the current
/// system's updater.
const RETRY_LIMIT: std::time::Duration = std::time::Duration::from_secs(90);

/// Sends `request` to the broker and returns its first response line and
/// the rest of its response. A broker that answers `RETRY` restarts into
/// the updater of the current system; the request goes again to the new
/// broker until `limit` passes.
fn send_apply_request(
    socket_path: &Path,
    request: &[u8],
    limit: std::time::Duration,
) -> Result<(String, UnixStream), String> {
    let deadline = std::time::Instant::now() + limit;
    let mut retry_reason = None;
    loop {
        let attempt = (|| {
            let mut socket = UnixStream::connect(socket_path).map_err(|error| error.to_string())?;
            // A broker that answers RETRY may close before it read the
            // request; its answer is still there to read.
            let sent = socket
                .write_all(request)
                .and_then(|()| socket.shutdown(Shutdown::Write));
            match protocol::read_control_line(&mut socket) {
                Ok(first) => Ok((first, socket)),
                Err(error) => Err(sent.err().map_or(error, |sent| sent.to_string())),
            }
        })();
        match attempt {
            Ok((first, socket)) => match first.strip_prefix(protocol::RETRY) {
                Some(reason) if reason.is_empty() || reason.starts_with(' ') => {
                    retry_reason = Some(reason.trim_start().to_owned());
                }
                _ => return Ok((first, socket)),
            },
            // Between two brokers the socket is briefly gone.
            Err(error) if retry_reason.is_none() => return Err(error),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "the update broker did not come back on the current updater: {}",
                retry_reason.unwrap_or_default()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// The request and its system, verified with the update account's trust
/// before the broker sees it.
fn checked_apply_request() -> Result<(Vec<u8>, std::path::PathBuf), String> {
    let mut request = Vec::new();
    io::stdin()
        .take(protocol::MAX_REQUEST)
        .read_to_end(&mut request)
        .map_err(|error| error.to_string())?;
    let request_text = std::str::from_utf8(&request).map_err(|_| "request is not UTF-8")?;
    let requested = protocol::parse_request(request_text)?;
    let system = verify::system(&requested)?;
    let mut stdout = io::stdout();
    stdout
        .write_all(protocol::Stage::Verifying.line().as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())?;
    let (static_keys, runtime_keys) = trust_from_environment()?;
    verify::closure(
        Path::new("/run/current-system/sw/bin/nix"),
        &system,
        &static_keys,
        runtime_keys.as_deref(),
    )?;
    Ok((request, system))
}

fn relay_apply_response(
    reader: &mut impl Read,
    writer: &mut impl Write,
    system: &Path,
) -> Result<(), String> {
    use protocol::SwitchLine;
    let mut activated = false;
    let mut failed = false;
    loop {
        let line = protocol::read_control_line(reader)?;
        let parsed = SwitchLine::parse(&line)?;
        let valid = match &parsed {
            SwitchLine::Activated(path) => path == system && !std::mem::replace(&mut activated, true),
            SwitchLine::Failed(_) => !std::mem::replace(&mut failed, true),
            SwitchLine::Ok(path) => path == system && !failed,
            _ => true,
        };
        if !valid {
            return Err("invalid broker activation response".into());
        }
        writeln!(writer, "{line}").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        if parsed.is_final() {
            let mut trailing = [0];
            if reader.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
                return Err("trailing broker response".into());
            }
            return match parsed.failure() {
                None => Ok(()),
                Some(failure) => Err(failure),
            };
        }
    }
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

#[cfg(test)]
mod rollback_relay_tests {
    use super::*;

    #[test]
    fn login_proxy_forwards_warnings_before_success() {
        let input = b"ACTIVATED /nix/store/test-system\nWARNING old.service was already failed\nOK /nix/store/test-system\n";
        let mut output = Vec::new();
        relay_apply_response(&mut &input[..], &mut output, Path::new("/nix/store/test-system")).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn login_proxy_forwards_failure_and_rollback_and_fails() {
        let input = b"ACTIVATED /nix/store/test-system\nFAILED status 4\nWAITING rollback\nROLLED-BACK status 4; restored\n";
        let mut output = Vec::new();
        let error = relay_apply_response(&mut &input[..], &mut output, Path::new("/nix/store/test-system")).unwrap_err();
        assert!(error.contains("rolled back: status 4; restored"), "{error}");
        assert_eq!(output, input);
        for bytes in [
            b"FAILED a\nFAILED b\n".as_slice(),
            b"FAILED a\nOK /nix/store/test-system\n",
            b"REJECTED x\ntrailing",
        ] {
            assert!(relay_apply_response(&mut &bytes[..], &mut Vec::new(), Path::new("/nix/store/test-system")).is_err());
        }
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    fn socket_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nur-retry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// A broker that answers RETRY and goes away, then its successor.
    #[test]
    fn a_login_sends_its_request_again_to_the_restarted_broker() {
        let dir = socket_dir();
        let path = dir.join("control.sock");
        let old = UnixListener::bind(&path).unwrap();
        let broker_path = path.clone();
        let broker = std::thread::spawn(move || {
            let (mut stream, _) = old.accept().unwrap();
            stream.write_all(b"RETRY the update daemon runs /a, but the update login of the current system is /b\n").unwrap();
            drop(stream);
            drop(old);
            std::fs::remove_file(&broker_path).unwrap();
            std::thread::sleep(Duration::from_millis(600));
            let new = UnixListener::bind(&broker_path).unwrap();
            let (mut stream, _) = new.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"OK /nix/store/test-system\n").unwrap();
            request
        });
        let (first, _) = send_apply_request(&path, b"REQUEST\n", Duration::from_secs(10)).unwrap();
        assert_eq!(first, "OK /nix/store/test-system");
        assert_eq!(broker.join().unwrap(), b"REQUEST\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_broker_that_never_comes_back_names_both_binaries() {
        let dir = socket_dir();
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let _ = stream.unwrap().write_all(b"RETRY the update daemon runs /a, but the update login of the current system is /b\n");
            }
        });
        let error = send_apply_request(&path, b"REQUEST\n", Duration::from_millis(800)).unwrap_err();
        assert!(error.contains("runs /a") && error.contains("system is /b"), "{error}");
        // Without a broker the login fails at once, as before.
        assert!(send_apply_request(&dir.join("missing"), b"REQUEST\n", Duration::from_secs(60)).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    fn directory(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nur-probe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn broker(path: &Path, answer: &'static [u8]) -> std::thread::JoinHandle<Vec<u8>> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(answer).unwrap();
            request
        })
    }

    #[test]
    fn a_ping_reports_the_broker_and_its_refusal() {
        let dir = directory("ping");
        let path = dir.join("control.sock");
        let served = broker(&path, b"PONG 0.1.0 /nix/store/abc-nix-update-remote/bin/nix-update-remote\n");
        let answer = ping(&path, Duration::from_secs(5)).unwrap();
        assert!(answer.contains("/nix/store/abc-nix-update-remote"), "{answer}");
        assert_eq!(served.join().unwrap(), protocol::ping_request().as_bytes());
        std::fs::remove_file(&path).unwrap();
        let served = broker(&path, b"REJECTED control peer has the wrong UID\n");
        assert!(ping(&path, Duration::from_secs(5)).unwrap_err().contains("wrong UID"));
        served.join().unwrap();
        std::fs::remove_file(&path).unwrap();
        // No broker at all: the probe fails once its retry window passes.
        let error = ping(&path, Duration::from_millis(600)).unwrap_err();
        assert!(error.contains("cannot reach the update broker"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_a_running_system_that_the_profile_names_is_committed() {
        // Two real store paths stand for two systems.
        let (Some(a), Some(b)) = (
            std::env::var_os("NIX_UPDATE_TEST_NIX"),
            std::env::var_os("NIX_UPDATE_TEST_COREUTILS"),
        ) else {
            panic!("NIX_UPDATE_TEST_NIX and NIX_UPDATE_TEST_COREUTILS must name store paths");
        };
        let dir = directory("committed");
        let (current, profile, link) = (dir.join("current"), dir.join("system"), dir.join("system-7-link"));
        symlink(&a, &current).unwrap();
        symlink(&a, &link).unwrap();
        symlink("system-7-link", &profile).unwrap();
        assert_eq!(committed_system(&current, &profile).unwrap(), std::fs::canonicalize(&a).unwrap());
        // Activated with `test` but not committed: the profile names another.
        std::fs::remove_file(&link).unwrap();
        symlink(&b, &link).unwrap();
        assert!(committed_system(&current, &profile).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod phase_tests {
    use super::*;

    #[test]
    fn the_login_answers_only_the_published_phase() {
        let dir = std::env::temp_dir().join(format!("nur-phase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let published = dir.join("transaction-phase");
        assert_eq!(transaction_phase(&published), Ok("idle"));
        for phase in ["activating", "committing"] {
            std::fs::write(&published, format!("{phase}\n")).unwrap();
            assert_eq!(transaction_phase(&published), Ok(phase));
        }
        // Anything else is no answer, never `idle`, and is not echoed.
        std::fs::write(&published, "{\"boot_id\":\"secret\"}\n").unwrap();
        let error = transaction_phase(&published).unwrap_err();
        assert!(!error.contains("secret"), "{error}");
        std::fs::remove_file(&published).unwrap();
        std::fs::create_dir(&published).unwrap();
        assert!(transaction_phase(&published).is_err(), "an unreadable phase is no answer");
        let _ = std::fs::remove_dir_all(dir);
    }
}
