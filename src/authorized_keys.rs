use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub fn run(args: &[String]) -> Result<(), String> {
    let [path, requested_user, configured_user] = args else {
        return Err("invalid authorized-keys arguments".into());
    };
    if requested_user != configured_user {
        return Err("authorized-keys user mismatch".into());
    }
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o400
    {
        return Err("SSH key file must be root-owned mode 0400".into());
    }
    io::stdout()
        .write_all(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}
