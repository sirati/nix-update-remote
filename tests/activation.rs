use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    let gate;
    let completion = match mode.as_str() {
        "server" => "/run/activation-gate-ready",
        // A start job that blocks until its file appears.
        "gate" => {
            gate = std::env::args().nth(2).ok_or("missing gate path")?;
            gate.as_str()
        }
        // The warning reporter: one line per report.
        "warn" => {
            use std::io::Write;
            let message = std::env::args().skip(2).collect::<Vec<_>>().join(" ");
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/root/warning-reports")?;
            writeln!(file, "{message}")?;
            return Ok(());
        }
        // The failure reporter: one line per report.
        "report" => {
            use std::io::Write;
            let message = std::env::args().skip(2).collect::<Vec<_>>().join(" ");
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/root/failure-reports")?;
            writeln!(file, "{message}")?;
            return Ok(());
        }
        // A secret deployment that waits for its operator.
        "secrets" => {
            fs::write("/root/secrets-started", b"started")?;
            let deadline = Instant::now() + Duration::from_secs(120);
            while !Path::new("/root/secrets-approve").is_file() {
                if Instant::now() >= deadline {
                    return Err("fixture timed out".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            fs::write("/root/secrets-deployed", b"deployed")?;
            return Ok(());
        }
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
