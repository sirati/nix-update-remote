use crate::protocol;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Options {
    target: String,
    installable: String,
    signing_key: Option<PathBuf>,
    key_command: Option<PathBuf>,
    key_args: Vec<String>,
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
                .spawn()
                .map_err(|e| e.to_string())?;
        let input = provider
            .stdout
            .take()
            .ok_or("missing key provider output")?;
        let signed = signing
            .arg("/proc/self/fd/0")
            .arg(&system)
            .stdin(Stdio::from(input))
            .status()
            .map_err(|e| e.to_string());
        let provided = provider.wait().map_err(|e| e.to_string())?;
        if !provided.success() || !signed?.success() {
            return Err("signing closure with key provider failed".into());
        }
    }
    let store = store_uri(&options.target)?;
    run(
        Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "copy",
                "--to",
            ])
            .arg(store)
            .arg(&system),
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
            .arg(store_uri(&options.target)?)
            .arg("--recursive")
            .arg(&system),
        "copying closure signatures",
    )?;
    apply(&options, &system)?;
    if let Some(command) = &options.post_command {
        run(
            Command::new(command).args(&options.post_args),
            "post-update operation",
        )?;
    }
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
    if signing_key.is_some() == key_command.is_some() {
        return Err("supply exactly one signing key or key command".into());
    }
    if !key_args.is_empty() && key_command.is_none() {
        return Err("key arguments require --key-command".into());
    }
    Ok(Options {
        target: target.ok_or("missing --target")?,
        installable: installable.ok_or("missing --installable")?,
        signing_key,
        key_command,
        key_args,
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
        .stderr(Stdio::inherit())
        .output()
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
struct ApplyChild(Child);
impl Drop for ApplyChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn apply(options: &Options, system: &Path) -> Result<(), String> {
    let target = &options.target;
    let mut child = ApplyChild(
        Command::new("ssh")
            .args(&options.ssh_args)
            .args(["--", target, "apply"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?,
    );
    child
        .0
        .stdin
        .take()
        .ok_or("missing SSH stdin")?
        .write_all(protocol::request(system).as_bytes())
        .map_err(|e| e.to_string())?;
    let expected = format!("OK {}\n", system.display());
    let mut callback_ran = false;
    if options.activation_command.is_some() {
        while child.0.try_wait().map_err(|e| e.to_string())?.is_none() {
            // This restricted read reports configuration activation, rather
            // than service readiness. /run/current-system changes after the
            // activation script installs /etc, before service start jobs end.
            // A repeated update can already have this same configuration.
            if current_system(target, &options.ssh_args, system)? {
                activation_callback(options)?;
                callback_ran = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let mut response = Vec::new();
    child
        .0
        .stdout
        .take()
        .ok_or("missing SSH stdout")?
        .take(protocol::MAX_REQUEST + 1)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    if response.len() > protocol::MAX_REQUEST as usize {
        return Err("remote switch response exceeds size limit".into());
    }
    let status = child.0.wait().map_err(|error| error.to_string())?;
    if !status.success() || response != expected.as_bytes() {
        return Err("remote switch failed or returned an invalid response".into());
    }
    // Fast activation may complete between polls. The successful broker
    // reply is stronger evidence, so the callback still runs exactly once.
    if !callback_ran {
        activation_callback(options)?;
    }
    println!("switched {} to {}", target, system.display());
    Ok(())
}

fn current_system(target: &str, ssh_args: &[String], system: &Path) -> Result<bool, String> {
    let mut query = ApplyChild(
        Command::new("ssh")
            .args(ssh_args)
            .args(["--", target, "current-system"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?,
    );
    let mut response = Vec::new();
    query
        .0
        .stdout
        .take()
        .ok_or("missing query stdout")?
        .take(protocol::MAX_REQUEST + 1)
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    if response.len() > protocol::MAX_REQUEST as usize {
        return Err("current-system response exceeds size limit".into());
    }
    let status = query.0.wait().map_err(|e| e.to_string())?;
    Ok(status.success() && response == format!("{}\n", system.display()).as_bytes())
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
        .status()
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
