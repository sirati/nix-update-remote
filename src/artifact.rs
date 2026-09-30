//! Signed EROFS adapter. The independent broker owns hooks and reboot.
use crate::{protocol, verify};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Options {
    root: PathBuf,
    key: PathBuf,
    signer: PathBuf,
    hash: PathBuf,
    bootstrap_tools: Option<[PathBuf; 3]>,
}
fn options(args: &[String]) -> Result<Options, String> {
    if args.len() != 4 && args.len() != 7 {
        return Err("artifact adapter needs ROOT PUBLIC_KEY SIGNER SHA512SUM".into());
    }
    let options = Options {
        root: PathBuf::from(&args[0]),
        key: PathBuf::from(&args[1]),
        signer: PathBuf::from(&args[2]),
        hash: PathBuf::from(&args[3]),
        bootstrap_tools: (args.len() == 7).then(|| {
            [
                PathBuf::from(&args[4]),
                PathBuf::from(&args[5]),
                PathBuf::from(&args[6]),
            ]
        }),
    };
    if !rustix::process::geteuid().is_root() {
        return Err("artifact adapter requires root".into());
    }
    if !options.root.is_absolute() || options.root.starts_with("/nix/store") {
        return Err("invalid artifact state root".into());
    }
    for executable in [&options.signer, &options.hash]
        .into_iter()
        .chain(options.bootstrap_tools.iter().flatten())
    {
        if !executable.is_absolute() || !executable.starts_with("/nix/store") {
            return Err("artifact tools must be immutable store executables".into());
        }
    }
    ensure_private_dir(&options.root)?;
    Ok(options)
}
fn ensure_private_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(error)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(error)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || fs::canonicalize(path).map_err(error)? != path
    {
        return Err("artifact directory must be canonical, root owned and private".into());
    }
    Ok(())
}
fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn valid_id(id: &str) -> bool {
    id.len() == 128
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(options: &Options, path: &Path) -> Result<String, String> {
    let output = Command::new(&options.hash)
        .env_clear()
        .arg(path)
        .output()
        .map_err(error)?;
    if !output.status.success() {
        return Err("hashing artifact failed".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(error)?;
    let id = text
        .split_whitespace()
        .next()
        .ok_or("hash tool returned no digest")?;
    if !valid_id(id) {
        return Err("hash tool returned invalid digest".into());
    }
    Ok(id.into())
}
fn signature(options: &Options, dir: &Path, name: &str, domain: &str) -> Result<(), String> {
    verify::checked(
        Command::new(&options.signer)
            .env_clear()
            .args(["verify", "--key"])
            .arg(&options.key)
            .args(["--domain", domain, "--sig"])
            .arg(dir.join(format!("{name}.sig")))
            .arg(dir.join(name)),
        "verifying artifact signature",
    )
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temporary(parent: &Path) -> Result<Temporary, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_nanos();
    let path = parent.join(format!(".incoming-{}-{stamp}", std::process::id()));
    fs::create_dir(&path).map_err(error)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(error)?;
    Ok(Temporary(path))
}
fn receive(reader: &mut impl Read, size: u64, path: &Path) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(error)?;
    if io::copy(&mut reader.take(size), &mut output).map_err(error)? != size {
        return Err("truncated artifact payload".into());
    }
    output.sync_all().map_err(error)
}
fn equal(left: &Path, right: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(right).map_err(error)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("existing artifact file is not protected".into());
    }
    let mut left = File::open(left).map_err(error)?;
    let mut right = File::open(right).map_err(error)?;
    if left.metadata().map_err(error)?.len() != right.metadata().map_err(error)?.len() {
        return Ok(false);
    }
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    loop {
        let count = left.read(&mut a).map_err(error)?;
        right.read_exact(&mut b[..count]).map_err(error)?;
        if a[..count] != b[..count] {
            return Ok(false);
        }
        if count == 0 {
            return Ok(true);
        }
    }
}
fn lock(root: &Path) -> Result<File, String> {
    let file = File::open(root).map_err(error)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).map_err(error)?;
    Ok(file)
}
fn prepare_impl(args: &[String]) -> Result<(String, bool), String> {
    let options = options(args)?;
    let mut input = io::stdin().lock();
    let mut fields = Vec::new();
    for _ in 0..17 {
        fields.push(protocol::read_control_line(&mut input)?);
    }
    if fields[0] != "NMBL-EROFS-BUNDLE-3" || !valid_id(&fields[1]) || !valid_id(&fields[5]) {
        return Err("invalid signed artifact header".into());
    }
    let mut sizes = Vec::new();
    for index in [2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        let value = &fields[index];
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid artifact size".into());
        }
        let size: u64 = value.parse().map_err(error)?;
        if size > 68719476736 {
            return Err("artifact exceeds size limit".into());
        }
        sizes.push(size);
    }

    for index in [0, 1, 3, 4, 5, 6, 7, 8, 9, 10] {
        if sizes[index] == 0 {
            return Err("empty artifact or signature".into());
        }
    }
    if (sizes[11] == 0) != (sizes[12] == 0) {
        return Err("incomplete network artifact".into());
    }
    let reboot = match fields[16].as_str() {
        "0" => false,
        "1" => true,
        _ => return Err("invalid reboot flag".into()),
    };
    // Small signed metadata must never cause an unbounded allocation or disk fill.
    for index in [1, 2, 3, 4, 6, 8, 10, 12] {
        if sizes[index] > 16 * 1024 * 1024 {
            return Err("artifact metadata exceeds size limit".into());
        }
    }
    let generations = options.root.join("generations");
    ensure_private_dir(&generations)?;
    let temporary = temporary(&generations)?;
    let names = [
        "nix.erofs",
        "nix.erofs.sig",
        "system",
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
    for (name, size) in names.iter().zip(&sizes) {
        if *size > 0 {
            receive(&mut input, *size, &temporary.0.join(name))?;
        }
    }
    let mut extra = [0];
    if input.read(&mut extra).map_err(error)? != 0 {
        return Err("trailing artifact protocol data".into());
    }
    if hash(&options, &temporary.0.join("nix.erofs"))? != fields[1]
        || hash(&options, &temporary.0.join("config.toml"))? != fields[5]
    {
        return Err("artifact content hash mismatch".into());
    }
    for (name, domain) in [
        ("nix.erofs", "generation-image"),
        ("config.toml", "boot-config"),
        ("kernel", "gen-kernel"),
        ("initrd", "gen-initrd"),
        ("rescue.sfs", "rescue-sfs"),
    ] {
        signature(&options, &temporary.0, name, domain)?;
    }
    if sizes[11] > 0 {
        signature(&options, &temporary.0, "network.erofs", "network-stage")?;
    }
    if let Some(tools) = &options.bootstrap_tools {
        verify::checked(
            Command::new(&tools[0])
                .env_clear()
                .args(["--mount", "--propagation", "private", "--"])
                .arg(std::env::current_exe().map_err(error)?)
                .arg("extract-bootstrap")
                .arg(temporary.0.join("nix.erofs"))
                .arg(&temporary.0)
                .arg(&tools[1])
                .arg(&tools[2]),
            "extracting authenticated bootstrap artifacts",
        )?;
    }
    // Kernel and initrd are verified boot payloads also contained in the signed image.
    fs::remove_file(temporary.0.join("kernel")).map_err(error)?;
    fs::remove_file(temporary.0.join("initrd")).map_err(error)?;
    // Unsigned system hint is never used as an activation target or report identity.
    if sizes[2] > 0 {
        fs::remove_file(temporary.0.join("system")).map_err(error)?;
    }
    fs::write(temporary.0.join("generation"), format!("{}\n", fields[1])).map_err(error)?;
    for entry in fs::read_dir(&temporary.0).map_err(error)? {
        let entry = entry.map_err(error)?;
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o444)).map_err(error)?;
        File::open(entry.path())
            .map_err(error)?
            .sync_all()
            .map_err(error)?;
    }
    File::open(&temporary.0)
        .map_err(error)?
        .sync_all()
        .map_err(error)?;
    let _guard = lock(&options.root)?;
    let destination = generations.join(&fields[1]);
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination).map_err(error)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err("existing generation directory is not protected".into());
        }
        for entry in fs::read_dir(&temporary.0).map_err(error)? {
            let entry = entry.map_err(error)?;
            // Both uploads are authenticated independently. Randomized
            // signatures can differ for identical payloads; activation
            // verifies the retained signatures before selecting this directory.
            if matches!(entry.file_name().to_str(), Some(
                "nix.erofs.sig" | "config.toml.sig" | "kernel.sig" |
                "initrd.sig" | "rescue.sfs.sig" | "network.erofs.sig"
            )) {
                continue;
            }
            if !equal(&entry.path(), &destination.join(entry.file_name()))? {
                return Err("existing generation differs from verified upload".into());
            }
        }
    } else {
        fs::rename(&temporary.0, &destination).map_err(error)?;
        File::open(&generations)
            .map_err(error)?
            .sync_all()
            .map_err(error)?;
    }
    Ok((fields[1].clone(), reboot))
}
fn selected(root: &Path, name: &str) -> Result<Option<String>, String> {
    let target = match fs::read_link(root.join(name)) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let text = target.to_str().ok_or("invalid generation selection")?;
    let id = text
        .strip_prefix("generations/")
        .ok_or("invalid generation selection")?;
    if !valid_id(id) || !root.join(&target).is_dir() {
        return Err("invalid generation selection".into());
    }
    Ok(Some(id.into()))
}
fn replace_link(root: &Path, name: &str, id: &str) -> Result<(), String> {
    let path = root.join(format!(".{name}.new.{}", std::process::id()));
    // Never remove an existing file we did not create.
    symlink(format!("generations/{id}"), &path).map_err(error)?;
    if let Err(error) = fs::rename(&path, root.join(name)) {
        let _ = fs::remove_file(&path);
        return Err(error.to_string());
    }
    File::open(root).map_err(error)?.sync_all().map_err(error)
}
fn remove_link(root: &Path, name: &str) -> Result<(), String> {
    match fs::remove_file(root.join(name)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
pub fn activate(args: &[String]) -> Result<(), String> {
    if (args.len() != 5 && args.len() != 8)
        || !valid_id(args.last().ok_or("missing generation id")?)
    {
        return Err("invalid artifact activation arguments".into());
    }
    let options = options(&args[..args.len() - 1])?;
    let id = args.last().ok_or("missing generation id")?;
    let _guard = lock(&options.root)?;
    let dir = options.root.join("generations").join(id);
    if hash(&options, &dir.join("nix.erofs"))? != *id {
        return Err("staged generation image hash mismatch".into());
    }
    for (name, domain) in [
        ("nix.erofs", "generation-image"),
        ("config.toml", "boot-config"),
        ("rescue.sfs", "rescue-sfs"),
    ] {
        signature(&options, &dir, name, domain)?;
    }
    if dir.join("network.erofs").exists() {
        signature(&options, &dir, "network.erofs", "network-stage")?;
    }
    if options.bootstrap_tools.is_some() {
        for name in ["bootstrap-kernel", "bootstrap-initrd"] {
            let metadata = fs::symlink_metadata(dir.join(name)).map_err(error)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.len() == 0
            {
                return Err("generation has no protected bootstrap artifact".into());
            }
        }
    }
    let old = selected(&options.root, "active")?;
    let tested = selected(&options.root, "tested")?;
    if let Some(old) = old.filter(|old| old != id) {
        replace_link(&options.root, "previous", &old)?;
    }
    replace_link(&options.root, "active", id)?;
    if tested.as_ref() == Some(id) {
        remove_link(&options.root, "pending")?;
    } else {
        replace_link(&options.root, "pending", id)?;
    }
    remove_link(&options.root, "attempted")?;
    remove_link(&options.root, "rollback-event")?;
    File::open(&options.root)
        .map_err(error)?
        .sync_all()
        .map_err(error)
}

/// This role runs only inside a private mount namespace created by the adapter.
pub fn extract_bootstrap(args: &[String]) -> Result<(), String> {
    if args.len() != 4 || !rustix::process::geteuid().is_root() {
        return Err("bootstrap extraction needs root and fixed arguments".into());
    }
    let image = PathBuf::from(&args[0]);
    let target = PathBuf::from(&args[1]);
    ensure_private_dir(&target)?;
    for tool in [&args[2], &args[3]] {
        if !tool.starts_with("/nix/store/") {
            return Err("mount tools must be immutable".into());
        }
    }
    let mountpoint = target.join(".bootstrap-mounted");
    fs::create_dir(&mountpoint).map_err(error)?;
    let mounted = verify::checked(
        Command::new(&args[2])
            .env_clear()
            .args(["-t", "erofs", "-o", "loop,ro,nodev,nosuid,noexec", "--"])
            .arg(&image)
            .arg(&mountpoint),
        "mounting verified generation image",
    );
    if let Err(error) = mounted {
        let _ = fs::remove_dir(&mountpoint);
        return Err(error);
    }
    let copied = (|| {
        let parent = fs::symlink_metadata(mountpoint.join("nmbl-bootstrap")).map_err(error)?;
        if !parent.is_dir() {
            return Err("bootstrap metadata directory must not be a symlink".into());
        }
        for (name, output) in [
            ("kernel", "bootstrap-kernel"),
            ("initrd", "bootstrap-initrd"),
        ] {
            let source = mountpoint.join("nmbl-bootstrap").join(name);
            let metadata = fs::symlink_metadata(&source).map_err(error)?;
            if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 68719476736 {
                return Err("signed image lacks a regular bootstrap artifact".into());
            }
            let mut input = File::open(source).map_err(error)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(target.join(output))
                .map_err(error)?;
            if io::copy(&mut input, &mut file).map_err(error)? != metadata.len() {
                return Err("bootstrap copy length mismatch".into());
            }
            file.sync_all().map_err(error)?;
        }
        Ok::<(), String>(())
    })();
    let unmounted = verify::checked(
        Command::new(&args[3])
            .env_clear()
            .arg("--")
            .arg(&mountpoint),
        "unmounting verified generation image",
    );
    if unmounted.is_ok() {
        fs::remove_dir(&mountpoint).map_err(error)?;
    }
    copied?;
    unmounted
}

pub fn prepare(args: &[String]) -> Result<(), String> {
    let (id, reboot) = prepare_impl(args)?;
    println!("NIX_UPDATE_ARTIFACT_READY_1\n{id}\n{}", u8::from(reboot));
    Ok(())
}
/// Initial provisioning only: run as root in the installation environment.
/// Installed machines use the restricted update account and broker instead.
pub fn install(args: &[String]) -> Result<(), String> {
    let (adapter_args, explicit_queue) =
        if args.len() >= 2 && args[args.len() - 2] == "--report-queue" {
            (
                &args[..args.len() - 2],
                Some(PathBuf::from(&args[args.len() - 1])),
            )
        } else {
            (args, None)
        };
    let (id, reboot) = prepare_impl(adapter_args)?;
    if reboot {
        return Err("initial provisioning must not request reboot".into());
    }
    let mut activation_args = adapter_args.to_vec();
    activation_args.push(id.clone());
    // Retain installation events for delivery by the installed reporting service.
    let queue = if let Some(queue) = explicit_queue {
        queue
    } else {
        Path::new(&adapter_args[0])
            .parent()
            .ok_or("generation root has no parent")?
            .join("system-update-reports")
    };
    let notify = |phase: &str, result: &str| {
        if let Err(error) = crate::report_queue::record(&queue, Path::new(&id), phase, result) {
            eprintln!("nix-update-remote: could not record installation notification: {error}");
        }
    };
    notify("before", "pending");
    let result = activate(&activation_args);
    notify("after", if result.is_ok() { "success" } else { "failure" });
    result?;
    println!("OK {id}");
    Ok(())
}
