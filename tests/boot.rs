//! Bootloader install hook fixture: probes /boot the way sirati-nmbl's
//! installer does, then records the default system like a boot entry. The
//! failing variant writes part of it first, then fails.
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let toplevel = std::env::args().nth(1).ok_or("missing toplevel")?;
    if !toplevel.starts_with("/nix/store/") {
        return Err("invalid toplevel".into());
    }
    if fs::write("/boot/.nmbl-test-write", b"").is_err() {
        return Err("/boot is not writable. Boot partition must be mounted read-write.".into());
    }
    fs::remove_file("/boot/.nmbl-test-write")?;
    fs::write("/boot/test-boot-default", format!("{toplevel}\n"))?;
    if cfg!(failing_install) {
        return Err("bootloader installation failed".into());
    }
    Ok(())
}
