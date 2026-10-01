use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    let completion = match mode.as_str() {
        "server" => "/run/activation-gate-ready",
        "client" => {
            let rooted = fs::read_dir(".")?.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("system-update-roots-")
                    && entry.path().join("system").is_symlink()
                    && entry.path().join("system").exists()
            });
            if !rooted {
                return Err("activation callback has no registered system root".into());
            }
            fs::write("/root/activation-callback-started", b"ready")?;
            "/root/activation-callback-finish"
        }
        _ => return Err("unknown fixture mode".into()),
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    while !Path::new(completion).is_file() {
        if Instant::now() >= deadline {
            return Err("fixture timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
