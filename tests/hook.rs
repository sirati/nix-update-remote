use std::fs::OpenOptions;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(blocked_report) {
        std::fs::write("/tmp/update-hook-blocked", b"waiting")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while std::path::Path::new("/tmp/update-hook-block").exists() {
            if std::time::Instant::now() >= deadline {
                return Err("report fixture timed out".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    let phase = std::env::var("UPDATE_PHASE")?;
    let result = std::env::var("UPDATE_RESULT")?;
    let system = std::env::var("UPDATE_SYSTEM")?;
    if !system.starts_with("/nix/store/") {
        return Err("invalid system path".into());
    }
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/update-hook-events")?,
        "{phase} {result} {system}"
    )?;
    Ok(())
}
