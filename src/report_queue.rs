//! Durable, nonblocking update events. Notifications cannot hold recovery hostage.
use crate::protocol;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn directory(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || root.starts_with("/nix/store") {
        return Err("invalid report queue path".into());
    }
    if !root.exists() {
        fs::create_dir_all(root).map_err(error)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(error)?;
    }
    let metadata = fs::symlink_metadata(root).map_err(error)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || fs::canonicalize(root).map_err(error)? != root
    {
        return Err("report queue must be canonical, root owned and private".into());
    }
    Ok(())
}
pub fn record(root: &Path, system: &Path, phase: &str, result: &str) -> Result<(), String> {
    directory(root)?;
    let system = system.to_str().ok_or("report system is not UTF-8")?;
    if system.len() > 1024 || system.contains(['\n', '\r']) {
        return Err("invalid report system".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?;
    let name = format!(
        "{}-{}-{}",
        now.as_nanos(),
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let temporary = root.join(format!(".{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(error)?;
    write!(
        file,
        "NIX_UPDATE_REPORT_1\n{phase}\n{result}\n{system}\n{}\n",
        now.as_secs()
    )
    .map_err(error)?;
    file.sync_all().map_err(error)?;
    fs::rename(temporary, root.join(format!("{name}.event"))).map_err(error)?;
    File::open(root).map_err(error)?.sync_all().map_err(error)
}
pub fn run_hook(args: &[String]) -> Result<(), String> {
    if args.len() != 8 {
        return Err("hook role needs UID GID PATH HOOK SYSTEM PHASE RESULT TIMESTAMP".into());
    }
    let uid: u32 = args[0].parse().map_err(error)?;
    let gid: u32 = args[1].parse().map_err(error)?;
    if uid == 0 || gid == 0 || !args[3].starts_with("/nix/store/") {
        return Err("hooks require an unprivileged identity and immutable executable".into());
    }
    rustix::thread::set_thread_groups(&[]).map_err(error)?;
    rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(gid)).map_err(error)?;
    rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(uid)).map_err(error)?;
    let mut command = Command::new(&args[3]);
    command
        .env_clear()
        .env("PATH", &args[2])
        .env("UPDATE_SYSTEM", &args[4])
        .env("UPDATE_PHASE", &args[5])
        .env("UPDATE_RESULT", &args[6])
        .env("UPDATE_EVENT_UNIX_SECONDS", &args[7]);
    Err(command.exec().to_string())
}
pub fn deliver(args: &[String]) -> Result<(), String> {
    if !rustix::process::geteuid().is_root() {
        return Err("queue delivery requires root".into());
    }
    let mut root = None;
    let mut uid = None;
    let mut gid = None;
    let mut path = "/run/current-system/sw/bin".to_owned();
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let value = iter.next().ok_or("missing delivery option value")?;
        match arg.as_str() {
            "--queue" => root = Some(PathBuf::from(value)),
            "--hook-uid" => uid = Some(value.clone()),
            "--hook-gid" => gid = Some(value.clone()),
            "--hook-path" => path = value.clone(),
            "--before-hook" => before.push(value.clone()),
            "--after-hook" => after.push(value.clone()),
            _ => return Err("invalid delivery option".into()),
        }
    }
    let root = root.ok_or("missing report queue")?;
    directory(&root)?;
    let uid = uid.ok_or("missing hook UID")?;
    let gid = gid.ok_or("missing hook GID")?;
    let lock = File::open(&root).map_err(error)?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(error)?;
    let mut entries = fs::read_dir(&root)
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut failed = false;
    for entry in entries {
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("event") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(error)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.len() > protocol::MAX_REQUEST
        {
            return Err("invalid queued report file".into());
        }
        let mut text = String::new();
        File::open(entry.path())
            .map_err(error)?
            .read_to_string(&mut text)
            .map_err(error)?;
        let fields: Vec<_> = text.lines().collect();
        if fields.len() != 5
            || fields[0] != "NIX_UPDATE_REPORT_1"
            || !matches!(fields[1], "before" | "after")
            || !matches!(fields[2], "pending" | "success" | "failure")
            || fields[4].parse::<u64>().is_err()
        {
            return Err("invalid queued report content".into());
        }
        let hooks = if fields[1] == "before" {
            &before
        } else {
            &after
        };
        // Keep queued events when reporting has been disabled, for later review/delivery.
        if hooks.is_empty() {
            failed = true;
            continue;
        }
        let mut delivered = true;
        for hook in hooks {
            let status = Command::new(std::env::current_exe().map_err(error)?)
                .args([
                    "run-hook", &uid, &gid, &path, hook, fields[3], fields[1], fields[2], fields[4],
                ])
                .status()
                .map_err(error)?;
            if !status.success() {
                eprintln!(
                    "nix-update-remote: pending {} report {}: hook failed",
                    fields[1],
                    entry.path().display()
                );
                delivered = false;
            }
        }
        if delivered {
            fs::remove_file(entry.path()).map_err(error)?;
            File::open(&root)
                .map_err(error)?
                .sync_all()
                .map_err(error)?;
        } else {
            failed = true;
        }
    }
    if failed {
        Err("update notifications remain queued for retry".into())
    } else {
        Ok(())
    }
}
