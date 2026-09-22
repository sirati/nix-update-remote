use crate::protocol;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Options {
    target: String,
    installable: String,
    signing_key: PathBuf,
    impure: bool,
}

pub fn deploy(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    validate_target(&options.target)?;
    validate_key(&options.signing_key)?;
    let system = build(&options)?;
    run(
        Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "store",
                "sign",
                "--recursive",
                "--key-file",
            ])
            .arg(&options.signing_key)
            .arg(&system),
        "signing closure",
    )?;
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
    apply(&options.target, &system)
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut target = None;
    let mut installable = None;
    let mut signing_key = None;
    let mut impure = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => target = iter.next().cloned(),
            "--installable" => installable = iter.next().cloned(),
            "--signing-key" => signing_key = iter.next().map(PathBuf::from),
            "--impure" => impure = true,
            _ => return Err(format!("unknown deploy argument: {arg}")),
        }
    }
    Ok(Options {
        target: target.ok_or("missing --target")?,
        installable: installable.ok_or("missing --installable")?,
        signing_key: signing_key.ok_or("missing --signing-key")?,
        impure,
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

fn build(options: &Options) -> Result<PathBuf, String> {
    let mut command = Command::new("nix");
    command.args([
        "--extra-experimental-features",
        "nix-command flakes",
        "build",
        "--no-link",
        "--print-out-paths",
    ]);
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

fn apply(target: &str, system: &Path) -> Result<(), String> {
    let mut child = Command::new("ssh")
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
