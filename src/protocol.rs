use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const MAGIC: &str = "NIX_UPDATE_REMOTE_1";
pub const SOCKET: &str = "/run/nix-update-remote/control.sock";
pub const MAX_REQUEST: u64 = 4096;

pub fn request(system: &Path) -> String {
    format!("{MAGIC}\nSWITCH\n{}\n", system.display())
}

pub fn parse_request(input: &str) -> Result<PathBuf, String> {
    let mut lines = input.lines();
    if lines.next() != Some(MAGIC) || lines.next() != Some("SWITCH") {
        return Err("invalid protocol header".into());
    }
    let path = lines.next().ok_or("missing system path")?;
    if lines.next().is_some() || !path.starts_with("/nix/store/") {
        return Err("invalid system path".into());
    }
    if path.contains("..")
        || path
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"/+._?=-".contains(&byte)))
    {
        return Err("invalid system path".into());
    }
    Ok(PathBuf::from(path))
}

pub fn read_runtime_trusted_keys(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o440
    {
        return Err("runtime trust file must be a root-owned regular file with mode 0440".into());
    }
    fs::read_to_string(path).map_err(|error| error.to_string())
}

pub fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(|error| error.to_string())
        }
        Ok(_) => Err("refusing to replace non-socket control path".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_canonical_store_path() {
        let input = format!("{MAGIC}\nSWITCH\n/nix/store/abc-system\n");
        assert_eq!(
            parse_request(&input).unwrap(),
            Path::new("/nix/store/abc-system")
        );
    }

    #[test]
    fn rejects_extra_actions_and_path_traversal() {
        assert!(parse_request(&format!("{MAGIC}\nSWITCH\n/nix/store/a\nMORE\n")).is_err());
        assert!(parse_request(&format!("{MAGIC}\nSWITCH\n/nix/store/../etc\n")).is_err());
        assert!(parse_request(&format!("{MAGIC}\nSWITCH\n/nix/store/a;id\n")).is_err());
    }
}

/// Consume a single bounded line without buffering bytes from the artifact stream.
pub fn read_control_line(stream: &mut impl std::io::Read) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|error| format!("reading control header: {error}"))?;
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_REQUEST as usize {
            return Err("control header too long".into());
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(|_| "control header is not UTF-8".into())
}

pub fn parse_artifact_receipt(bytes: &[u8]) -> Result<(PathBuf, bool), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "backend receipt is not UTF-8")?;
    let mut lines = text.lines();
    if lines.next() != Some("NIX_UPDATE_ARTIFACT_READY_1") {
        return Err("invalid backend receipt".into());
    }
    let system = lines.next().ok_or("backend receipt lacks candidate")?;
    if system.is_empty()
        || system.len() > 1024
        || !system
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
    {
        return Err("invalid backend candidate".into());
    }
    let reboot = match lines.next() {
        Some("0") => false,
        Some("1") => true,
        _ => return Err("invalid backend reboot flag".into()),
    };
    if lines.next().is_some() {
        return Err("trailing backend receipt data".into());
    }
    Ok((PathBuf::from(system), reboot))
}
