use crate::protocol;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Options {
    target: String,
    installable: String,
    signing_key: Option<PathBuf>,
    key_command: Option<PathBuf>,
    key_args: Vec<String>,
    impure: bool,
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
    apply(&options.target, &system, &options.ssh_args)?;
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

fn apply(target: &str, system: &Path, ssh_args: &[String]) -> Result<(), String> {
    let mut child = Command::new("ssh")
        .args(ssh_args)
        .args(["--", target, "apply"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .take()
        .ok_or("missing SSH stdin")?
        .write_all(protocol::request(system).as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let expected = format!("OK {}\n", system.display());
    if !output.status.success() || output.stdout != expected.as_bytes() {
        return Err("remote switch failed or returned an invalid response".into());
    }
    println!("switched {} to {}", target, system.display());
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
