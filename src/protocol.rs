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

/// Most bytes of free text in one response line.
pub const MAX_REASON: usize = 2000;

/// Free text as one bounded response line without control characters.
pub fn one_line(text: &str) -> String {
    let mut line = String::new();
    for character in text.chars() {
        let character = if character.is_control() { ' ' } else { character };
        if line.len() + character.len_utf8() > MAX_REASON {
            break;
        }
        line.push(character);
    }
    line
}

/// One line of the closure switch response, as the broker sends it.
#[derive(Debug, PartialEq, Eq)]
pub enum SwitchLine {
    Activated(PathBuf),
    Failed(String),
    /// Still working. Its text is free, except that `stage WORD` announces
    /// the [`Stage`] the host enters; clients that predate stages ignore it.
    Waiting(String),
    /// Committed, but the operator must see this.
    Warning(String),
    Ok(PathBuf),
    /// Nothing changed on the host. Legacy brokers give no reason.
    Rejected(String),
    RolledBack(String),
    RollbackFailed(String),
}

impl SwitchLine {
    pub fn parse(line: &str) -> Result<Self, String> {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        Ok(match word {
            "ACTIVATED" => SwitchLine::Activated(PathBuf::from(rest)),
            "FAILED" => SwitchLine::Failed(rest.to_owned()),
            "WAITING" => SwitchLine::Waiting(rest.to_owned()),
            "WARNING" => SwitchLine::Warning(rest.to_owned()),
            "OK" => SwitchLine::Ok(PathBuf::from(rest)),
            "REJECTED" => SwitchLine::Rejected(rest.to_owned()),
            "ROLLED-BACK" => SwitchLine::RolledBack(rest.to_owned()),
            "ROLLBACK-FAILED" => SwitchLine::RollbackFailed(rest.to_owned()),
            _ if line == "ERR update rejected" => SwitchLine::Rejected(String::new()),
            _ => return Err("invalid remote switch response".into()),
        })
    }

    pub fn is_final(&self) -> bool {
        !matches!(
            self,
            SwitchLine::Activated(_) | SwitchLine::Failed(_) | SwitchLine::Waiting(_) | SwitchLine::Warning(_)
        )
    }

    /// The stage a `WAITING stage WORD` line announces.
    pub fn stage(&self) -> Option<Stage> {
        match self {
            SwitchLine::Waiting(text) => text.strip_prefix("stage ").and_then(Stage::parse),
            _ => None,
        }
    }

    /// What the operator is told about a final line other than `OK`.
    pub fn failure(&self) -> Option<String> {
        let reason = |text: &str| if text.is_empty() { String::new() } else { format!(": {text}") };
        match self {
            SwitchLine::Rejected(text) => Some(format!("update rejected, the host is unchanged{}", reason(text))),
            SwitchLine::RolledBack(text) => Some(format!("update failed and was rolled back{}", reason(text))),
            SwitchLine::RollbackFailed(text) => Some(format!(
                "update failed and ROLLING BACK FAILED, the host needs attention{}",
                reason(text)
            )),
            _ => None,
        }
    }
}

/// What the host does with an update, as it starts doing it. The broker
/// announces each stage in a `WAITING stage WORD` line, which a client that
/// predates stages takes for a keepalive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Checking the closure's signatures by an update key.
    Verifying,
    /// `switch-to-configuration test` of the new system.
    Activating,
    /// The health gate of the new system.
    HealthGate,
    /// Setting the profile and the bootloader to the new system.
    Committing,
    /// Restoring the previous system.
    RollingBack,
}

impl Stage {
    pub const ALL: [Stage; 5] = [
        Stage::Verifying,
        Stage::Activating,
        Stage::HealthGate,
        Stage::Committing,
        Stage::RollingBack,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Stage::Verifying => "verifying",
            Stage::Activating => "activating",
            Stage::HealthGate => "health-gate",
            Stage::Committing => "committing",
            Stage::RollingBack => "rolling-back",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|stage| stage.word() == word)
    }

    /// The line that announces this stage.
    pub fn line(self) -> String {
        format!("WAITING stage {}\n", self.word())
    }

    /// What the operator reads.
    pub fn describe(self) -> &'static str {
        match self {
            Stage::Verifying => "verifying the closure signatures on the host",
            Stage::Activating => "activating the new system",
            Stage::HealthGate => "checking the health of the new system",
            Stage::Committing => "committing the new system to the profile and bootloader",
            Stage::RollingBack => "rolling back to the previous system",
        }
    }
}

/// The broker's first line when it does not run the current system's
/// updater: it restarts into that updater, and the login helper sends the
/// request again.
pub const RETRY: &str = "RETRY";

#[cfg(test)]
mod switch_line_tests {
    use super::*;

    #[test]
    fn responses_keep_their_kind_and_reason() {
        assert_eq!(SwitchLine::parse("ERR update rejected").unwrap(), SwitchLine::Rejected(String::new()));
        assert_eq!(
            SwitchLine::parse("ROLLED-BACK units failed: a.service").unwrap(),
            SwitchLine::RolledBack("units failed: a.service".into())
        );
        assert!(SwitchLine::parse("ROLLED-BACK x").unwrap().failure().unwrap().contains("rolled back: x"));
        assert!(SwitchLine::parse("REJECTED x").unwrap().failure().unwrap().contains("unchanged"));
        assert!(!SwitchLine::parse("FAILED x").unwrap().is_final());
        for stage in Stage::ALL {
            let parsed = SwitchLine::parse(stage.line().trim_end()).unwrap();
            assert!(!parsed.is_final());
            assert_eq!(parsed.stage(), Some(stage));
        }
        assert_eq!(SwitchLine::parse("WAITING switch-to-configuration test").unwrap().stage(), None);
        assert_eq!(SwitchLine::parse("WAITING stage dancing").unwrap().stage(), None);
        assert_eq!(SwitchLine::parse("WARNING a.service").unwrap(), SwitchLine::Warning("a.service".into()));
        assert!(!SwitchLine::parse("WARNING a").unwrap().is_final());
        assert!(SwitchLine::parse("SOMETHING").is_err());
        assert_eq!(one_line("a\nb\x1b"), "a b ");
        assert_eq!(one_line(&"é".repeat(MAX_REASON)).len(), MAX_REASON);
    }
}
