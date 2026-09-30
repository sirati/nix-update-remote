//! Generic operator key generator: secret on stdout, public half on fd 3.
use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Command, Stdio};
pub fn generate(args: &[String]) -> Result<(), String> {
    let name = match args {
        [name]
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) =>
        {
            name
        }
        _ => return Err("usage: keygen SIGNING-KEY-NAME".into()),
    };
    let public = OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")
        .map_err(|_| "public output fd 3 is unavailable")?;
    let generated = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "key",
            "generate-secret",
            "--key-name",
            name,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !generated.status.success() {
        return Err("generating signing key failed".into());
    }
    let mut private = generated.stdout;
    let result = (|| {
        let mut child = Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "key",
                "convert-secret-to-public",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(public))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let written = child
            .stdin
            .take()
            .ok_or("missing public derivation input")?
            .write_all(&private)
            .map_err(|e| e.to_string());
        let status = child.wait().map_err(|e| e.to_string())?;
        written?;
        if !status.success() {
            return Err("deriving signing public key failed".into());
        }
        std::io::stdout()
            .lock()
            .write_all(&private)
            .map_err(|e| e.to_string())
    })();
    private.fill(0);
    result
}
