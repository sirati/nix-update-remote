use crate::cancellation::ManagedCommand;
use crate::protocol;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
}

pub fn deploy(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    validate_target(&options.target)?;
    if let Some(key) = &options.signing_key {
        validate_key(key)?;
    }
    let roots = Roots::create()?;
    let system = build(&options, &roots.0.join("system"))?;
    if let Some(command) = &options.sign_command {
        crate::closure_signing::sign(&system, &roots.0, command, &options.sign_args)?;
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
    let transport = Transport::connect(&options)?;
    let store = format!("{}?max-connections=1", store_uri(&options.target)?);
    copy_closure(&system, &store, &transport)?;
    apply(&options, &system, &transport)?;
    if let Some(command) = &options.post_command {
        run(
            Command::new(command).args(&options.post_args),
            "post-update operation",
        )?;
    }
    Ok(())
}

fn copy_closure(system: &Path, store: &str, transport: &Transport) -> Result<(), String> {
    run(
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
    )?;
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
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
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
            _ => return Err(format!("unknown deploy argument: {arg}")),
        }
    }
    if !activation_args.is_empty() && activation_command.is_none() {
        return Err("activation arguments require --activation-command".into());
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
// activation already in progress continues under the root broker.
struct ApplyChild(crate::cancellation::ManagedChild);
impl Drop for ApplyChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn apply(options: &Options, system: &Path, transport: &Transport) -> Result<(), String> {
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
    let mut response = TimedResponse(child.0.stdout.take().ok_or("missing SSH stdout")?);
    let mut callback_ran = false;
    let final_line = consume_progress(&mut response, system, || {
        activation_callback(options)?;
        callback_ran = true;
        Ok(())
    })?;
    let status = child.0.wait().map_err(|error| error.to_string())?;
    if !status.success() || final_line != format!("OK {}", system.display()) {
        return Err("remote switch failed or returned an invalid response".into());
    }
    // Legacy brokers emit only the final receipt. Successful completion
    // still runs the callback exactly once without opening another channel.
    if !callback_ran {
        activation_callback(options)?;
    }
    println!("switched {} to {}", target, system.display());
    Ok(())
}

struct TimedResponse(std::process::ChildStdout);
impl Read for TimedResponse {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let mut descriptors = [PollFd::new(&self.0, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 600,
            tv_nsec: 0,
        };
        if poll(&mut descriptors, Some(&timeout))? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "remote activation produced no progress for 10 minutes; an older broker may need secrets deployed before this upgrade",
            ));
        }
        self.0.read(bytes)
    }
}

fn consume_progress(
    reader: &mut impl Read,
    system: &Path,
    mut activated: impl FnMut() -> Result<(), String>,
) -> Result<String, String> {
    let expected = format!("ACTIVATED {}", system.display());
    let mut seen = false;
    for _ in 0..2 {
        let line = protocol::read_control_line(reader)?;
        if line == expected && !seen {
            seen = true;
            activated()?;
        } else if line == format!("OK {}", system.display()) || line == "ERR update rejected" {
            let mut byte = [0];
            if reader.read(&mut byte).map_err(|e| e.to_string())? != 0 {
                return Err("trailing remote switch response".into());
            }
            return Ok(line);
        } else {
            return Err("invalid or duplicate activation progress event".into());
        }
    }
    Err("missing final remote switch result".into())
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

fn activation_callback(options: &Options) -> Result<(), String> {
    if let Some(command) = &options.activation_command {
        run(
            Command::new(command).args(&options.activation_args),
            "configuration activation operation",
        )?;
    }
    Ok(())
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
        copy_closure(&system, &store, &transport).unwrap();
        let mut master = transport.master.take().unwrap();
        master.kill().unwrap();
        master.wait().unwrap();
        assert!(
            copy_closure(&system, &store, &transport).is_err(),
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
        let (mut server, mut client) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (notice, confirmed) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            server
                .write_all(b"ACTIVATED /nix/store/test-system\n")
                .unwrap();
            confirmed.recv_timeout(Duration::from_secs(2)).unwrap();
            server.write_all(b"OK /nix/store/test-system\n").unwrap();
        });
        let mut callbacks = 0;
        let receipt = consume_progress(&mut client, Path::new("/nix/store/test-system"), || {
            callbacks += 1;
            notice.send(()).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(callbacks, 1);
        assert_eq!(receipt, "OK /nix/store/test-system");
        writer.join().unwrap();
    }
    #[test]
    fn progress_is_not_final_success_and_invalid_events_are_rejected() {
        let system = Path::new("/nix/store/test-system");
        let mut callbacks = 0;
        let result = consume_progress(
            &mut &b"ACTIVATED /nix/store/test-system\nERR update rejected\n"[..],
            system,
            || {
                callbacks += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(callbacks, 1);
        assert_eq!(result, "ERR update rejected");
        for bytes in [
            b"ACTIVATED /nix/store/wrong\n".as_slice(),
            b"ACTIVATED /nix/store/test-system\nACTIVATED /nix/store/test-system\n",
            b"OK /nix/store/test-system\nextra",
            b"ACTIVATED /nix/store/test-system\n",
        ] {
            assert!(consume_progress(&mut &bytes[..], system, || Ok(())).is_err());
        }
        let mut callbacks = 0;
        assert_eq!(
            consume_progress(&mut &b"OK /nix/store/test-system\n"[..], system, || {
                callbacks += 1;
                Ok(())
            })
            .unwrap(),
            "OK /nix/store/test-system"
        );
        assert_eq!(callbacks, 0); // apply owns legacy completion callback.
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
