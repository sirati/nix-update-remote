use std::fs::OpenOptions;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
