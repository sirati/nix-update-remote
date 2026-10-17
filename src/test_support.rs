//! Helpers shared by unit tests.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Installs `#!/bin/sh` and `body` as an executable at `path`. The test
/// process never opens it for writing: a fork by another test running
/// meanwhile would inherit that descriptor, and every exec of the script
/// fails with ETXTBSY until the forked child execs in turn.
pub fn install_script(path: &Path, body: &str) {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
    assert!(child.wait().unwrap().success(), "cannot write {}", path.display());
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
