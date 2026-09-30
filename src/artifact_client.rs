//! Operator path for signing and uploading a prepared artifact set.
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn deploy(args: &[String]) -> Result<(), String> {
    let mut target = None;
    let mut key = None;
    let mut signer = None;
    let mut hash = None;
    let mut key_command = None;
    let mut key_args = Vec::new();
    let mut ssh_command = "ssh".to_owned();
    let mut ssh_args = Vec::new();
    let mut remote_command = None;
    let mut remote_args = Vec::new();
    let mut sources = std::collections::BTreeMap::new();
    let mut reboot = false;
    let mut post_command = None;
    let mut post_args = Vec::new();
    let mut wait_system = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--remote-command" => remote_command = iter.next().cloned(),
            "--remote-arg" => {
                remote_args.push(iter.next().ok_or("missing remote argument")?.clone())
            }
            "--post-command" => post_command = iter.next().cloned(),
            "--post-arg" => {
                post_args.push(iter.next().ok_or("missing post-update argument")?.clone())
            }
            "--wait-system" => wait_system = iter.next().cloned(),
            "--key-command" => key_command = iter.next().cloned(),
            "--key-arg" => key_args.push(iter.next().ok_or("missing key argument")?.clone()),
            "--ssh-command" => ssh_command = iter.next().ok_or("missing SSH executable")?.clone(),
            "--ssh-arg" => ssh_args.push(iter.next().ok_or("missing SSH argument")?.clone()),
            "--target" => target = iter.next().cloned(),
            "--signing-key" => key = iter.next().map(PathBuf::from),
            "--signer" => signer = iter.next().map(PathBuf::from),
            "--sha512sum" => hash = iter.next().map(PathBuf::from),
            "--reboot" => reboot = true,
            "--image" | "--config" | "--kernel" | "--initrd" | "--rescue" | "--network" => {
                let value = iter.next().ok_or("missing artifact path")?;
                sources.insert(arg.as_str(), PathBuf::from(value));
            }
            _ => return Err(format!("unknown artifact deploy argument: {arg}")),
        }
    }
    if post_command.is_some() && reboot && wait_system.is_none() {
        return Err(
            "post-update operation requires the expected --wait-system after reboot".into(),
        );
    }
    let target = target.ok_or("missing target")?;
    if target.starts_with('-')
        || target.matches('@').count() != 1
        || target.chars().any(char::is_whitespace)
    {
        return Err("invalid SSH target".into());
    }
    if key.is_some() == key_command.is_some() {
        return Err("supply exactly one signing key file or structured key command".into());
    }
    if let Some(key) = &key {
        if key.starts_with("/nix/store") || !key.is_file() {
            return Err("signing key must be a file outside the Nix store".into());
        }
    }
    let signer = signer.ok_or("missing signer")?;
    let hash = hash.ok_or("missing sha512sum")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let temporary = Temporary(
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(format!("system-update-{}-{stamp}", std::process::id())),
    );
    fs::create_dir(&temporary.0).map_err(|e| e.to_string())?;
    fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    eprintln!(
        "Retaining signed update artifacts in {} until completion",
        temporary.0.display()
    );
    let definitions = [
        ("--image", "nix.erofs", "generation-image"),
        ("--config", "config.toml", "boot-config"),
        ("--kernel", "kernel", "gen-kernel"),
        ("--initrd", "initrd", "gen-initrd"),
        ("--rescue", "rescue.sfs", "rescue-sfs"),
        ("--network", "network.erofs", "network-stage"),
    ];
    for (option, name, domain) in definitions {
        let Some(source) = sources.get(option) else {
            if option == "--network" {
                continue;
            }
            return Err(format!("missing {option}"));
        };
        let path = temporary.0.join(name);
        fs::copy(source, &path).map_err(|e| e.to_string())?;
        let mut sign = Command::new(&signer);
        let mut provider = None;
        if let Some(key) = &key {
            sign.arg("sign").arg("--key").arg(key);
        } else {
            let mut child = Command::new(key_command.as_ref().ok_or("missing key provider")?)
                .args(&key_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| e.to_string())?;
            sign.args(["sign", "--key-stdin"]).stdin(
                child
                    .stdout
                    .take()
                    .ok_or("key provider stdout is missing")?,
            );
            provider = Some(child);
        }
        let signing = sign
            .args(["--domain", domain, "--out"])
            .arg(temporary.0.join(format!("{name}.sig")))
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| e.to_string());
        let mut provider_ok = true;
        if let Some(mut child) = provider {
            provider_ok = child.wait().map_err(|e| e.to_string())?.success();
        }
        if !signing?.success() || !provider_ok {
            return Err("signing update artifact failed".into());
        }
    }
    let digest = |name: &str| -> Result<String, String> {
        let output = Command::new(&hash)
            .arg(temporary.0.join(name))
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("hashing update failed".into());
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
        Ok(text
            .split_whitespace()
            .next()
            .ok_or("missing digest")?
            .into())
    };
    let id = digest("nix.erofs")?;
    let config_id = digest("config.toml")?;
    let names = [
        "nix.erofs",
        "nix.erofs.sig",
        "config.toml",
        "config.toml.sig",
        "kernel",
        "kernel.sig",
        "initrd",
        "initrd.sig",
        "rescue.sfs",
        "rescue.sfs.sig",
        "network.erofs",
        "network.erofs.sig",
    ];
    let mut sizes = Vec::new();
    for name in names {
        sizes.push(
            fs::metadata(temporary.0.join(name))
                .map(|m| m.len())
                .unwrap_or(0),
        );
    }
    let header = format!(
        "NMBL-EROFS-BUNDLE-3\n{id}\n{}\n{}\n0\n{config_id}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        sizes[0],
        sizes[1],
        sizes[2],
        sizes[3],
        sizes[4],
        sizes[5],
        sizes[6],
        sizes[7],
        sizes[8],
        sizes[9],
        sizes[10],
        sizes[11],
        u8::from(reboot)
    );
    let remote = if let Some(command) = remote_command {
        let quoted = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        std::iter::once(command)
            .chain(remote_args)
            .map(|word| quoted(&word))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        if !remote_args.is_empty() {
            return Err("remote arguments need an explicit provisioning command".into());
        }
        "nmbl-erofs-receive".to_owned()
    };
    let mut ssh = Command::new(&ssh_command)
        .args(&ssh_args)
        .args(["--", &target, &remote])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| e.to_string())?;
    let send = (|| {
        let mut input = ssh.stdin.take().ok_or("missing SSH input")?;
        input
            .write_all(header.as_bytes())
            .map_err(|e| e.to_string())?;
        for name in names {
            let path = temporary.0.join(name);
            if path.exists() {
                io::copy(
                    &mut File::open(path).map_err(|e| e.to_string())?,
                    &mut input,
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok::<(), String>(())
    })();
    let status = ssh.wait().map_err(|e| e.to_string())?;
    send?;
    if !status.success() {
        return Err("signed artifact update failed".into());
    }
    if let Some(expected) = wait_system {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            let output = Command::new(&ssh_command)
                .args(&ssh_args)
                .args(["--", &target, "current-system"])
                .output()
                .map_err(|e| e.to_string())?;
            if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == expected
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(
                    "selected system did not return after update within five minutes".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    if let Some(command) = post_command {
        if !reboot {
            eprintln!("Post-update operation deferred because reboot was not requested");
        } else {
            let status = Command::new(command)
                .args(post_args)
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(
                    "update succeeded but the configured post-update operation failed".into(),
                );
            }
        }
    }
    Ok(())
}
