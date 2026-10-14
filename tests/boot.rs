//! Bootloader install hook fixture: records the default system like a boot
//! entry. The failing variant writes part of it first, then fails.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let toplevel = std::env::args().nth(1).ok_or("missing toplevel")?;
    if !toplevel.starts_with("/nix/store/") {
        return Err("invalid toplevel".into());
    }
    std::fs::create_dir_all("/var/lib/test-boot")?;
    std::fs::write("/var/lib/test-boot/default", format!("{toplevel}\n"))?;
    if cfg!(failing_install) {
        return Err("bootloader installation failed".into());
    }
    Ok(())
}
