//! Generic signature-only signing of standard Nix closure metadata.
use crate::{cancellation::ManagedCommand, external_signing};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
const LIMIT: usize = 4 * 1024 * 1024;
const ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
#[derive(Debug, Serialize)]
struct Request {
    version: u32,
    paths: Vec<PathInfo>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawInfo {
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    signatures: Vec<Signature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    path: String,
    signature: String,
}
fn store_path(path: &str) -> Result<(), String> {
    let base = path
        .strip_prefix("/nix/store/")
        .ok_or("noncanonical store path")?;
    let (hash, name) = base.split_once('-').ok_or("invalid store basename")?;
    if hash.len() != 32
        || !hash.bytes().all(|b| ALPHABET.contains(&b))
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+._?=-".contains(&b))
    {
        return Err("invalid store basename".into());
    }
    Ok(())
}
fn nix32(bytes: &[u8]) -> String {
    (0..(bytes.len() * 8).div_ceil(5))
        .rev()
        .map(|i| {
            let bit = i * 5;
            let mut n = bytes[bit / 8] >> (bit % 8);
            if bit % 8 != 0 && bit / 8 + 1 < bytes.len() {
                n |= bytes[bit / 8 + 1] << (8 - bit % 8);
            }
            ALPHABET[(n & 31) as usize] as char
        })
        .collect()
}
fn canonical_hash(hash: &str) -> Result<String, String> {
    if let Some(value) = hash.strip_prefix("sha256:") {
        if value.len() == 52
            && value.bytes().all(|b| ALPHABET.contains(&b))
            && value.as_bytes()[0] <= b'1'
        {
            return Ok(hash.into());
        }
    }
    let bytes = external_signing::decode(
        hash.strip_prefix("sha256-")
            .ok_or("NAR hash must be SHA256")?,
    )?;
    if bytes.len() != 32 {
        return Err("invalid SHA256 length".into());
    }
    Ok(format!("sha256:{}", nix32(&bytes)))
}
fn manifest(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len() > LIMIT {
        return Err("closure metadata exceeds limit".into());
    }
    let input: BTreeMap<String, RawInfo> =
        serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if input.is_empty() || input.len() > 4096 {
        return Err("invalid closure path count".into());
    }
    let mut paths = Vec::new();
    for (path, info) in input {
        store_path(&path)?;
        if info.nar_size == 0 || info.references.len() > 4096 {
            return Err("invalid NAR metadata".into());
        }
        let mut references = info.references;
        for reference in &references {
            store_path(reference)?;
        }
        references.sort();
        if references.windows(2).any(|w| w[0] == w[1]) {
            return Err("duplicate closure reference".into());
        }
        paths.push(PathInfo {
            path,
            nar_hash: canonical_hash(&info.nar_hash)?,
            nar_size: info.nar_size,
            references,
        });
    }
    Ok(Request { version: 1, paths })
}
fn signatures(request: &Request, bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let response: Response = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if response.version != 1 || response.signatures.len() != request.paths.len() {
        return Err("signature response version/count differs".into());
    }
    let mut result = BTreeMap::new();
    for item in response.signatures {
        if !request.paths.iter().any(|p| p.path == item.path) {
            return Err("signature names unexpected path".into());
        }
        let (name, encoded) = item
            .signature
            .split_once(':')
            .ok_or("unnamed Nix signature")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || external_signing::decode(encoded)?.len() != 64
        {
            return Err("invalid Nix Ed25519 signature".into());
        }
        if result.insert(item.path, item.signature).is_some() {
            return Err("duplicate signed path".into());
        }
    }
    Ok(result)
}
fn narinfo(info: &PathInfo, signature: &str) -> String {
    let refs = info
        .references
        .iter()
        .map(|p| p.strip_prefix("/nix/store/").expect("validated store path"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "StorePath: {}\nURL: metadata-only.nar\nCompression: none\nNarHash: {}\nNarSize: {}\nReferences: {}\nSig: {}\n",
        info.path, info.nar_hash, info.nar_size, refs, signature
    )
}
pub fn sign(system: &Path, roots: &Path, command: &Path, args: &[String]) -> Result<(), String> {
    let output = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--recursive",
            "--json",
        ])
        .arg(system)
        .managed_output_inherit_stderr()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("querying public closure metadata failed".into());
    }
    let request = manifest(&output.stdout)?;
    if !request.paths.iter().any(|p| Path::new(&p.path) == system) {
        return Err("closure metadata omits system".into());
    }
    let input = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let response = external_signing::exchange_limit(
        command.to_str().ok_or("non-UTF8 signer path")?,
        args,
        input,
        LIMIT,
    )?;
    let signed = signatures(&request, &response)?;
    let cache = roots.join("signature-cache");
    fs::create_dir(&cache).map_err(|e| e.to_string())?;
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    fs::write(
        cache.join("nix-cache-info"),
        "StoreDir: /nix/store\nWantMassQuery: 0\nPriority: 50\n",
    )
    .map_err(|e| e.to_string())?;
    for info in &request.paths {
        let hash = info
            .path
            .strip_prefix("/nix/store/")
            .expect("validated store path")
            .split_once('-')
            .expect("validated basename")
            .0;
        fs::write(
            cache.join(format!("{hash}.narinfo")),
            narinfo(info, &signed[&info.path]),
        )
        .map_err(|e| e.to_string())?;
    }
    let status = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "store",
            "copy-sigs",
            "--substituter",
        ])
        .arg(format!("file://{}", cache.display()))
        .arg("--recursive")
        .arg(system)
        .managed_status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("importing external closure signatures failed".into());
    }
    let imported = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command",
            "path-info",
            "--recursive",
            "--json",
        ])
        .arg(system)
        .managed_output_inherit_stderr()
        .map_err(|e| e.to_string())?;
    if !imported.status.success() {
        return Err("checking imported signatures failed".into());
    }
    let observed: serde_json::Value =
        serde_json::from_slice(&imported.stdout).map_err(|e| e.to_string())?;
    for (path, signature) in signed {
        if !observed[&path]["signatures"]
            .as_array()
            .is_some_and(|s| s.iter().any(|v| v.as_str() == Some(&signature)))
        {
            return Err("Nix did not import an exact requested signature".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn path() -> &'static str {
        "/nix/store/00000000000000000000000000000000-system"
    }
    fn request() -> Request {
        manifest(serde_json::json!({path(): {"narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize": 13, "references": []}}).to_string().as_bytes()).unwrap()
    }
    #[test]
    fn canonical_hash_and_narinfo_binding() {
        let request = request();
        assert_eq!(
            request.paths[0].nar_hash,
            format!("sha256:{}", "0".repeat(52))
        );
        assert_eq!(nix32(&[255; 32]), format!("1{}", "z".repeat(51)));
        let text = narinfo(&request.paths[0], "key:public");
        assert!(text.contains("NarSize: 13\nReferences: \nSig: key:public\n"));
        assert!(!text.contains("private"));
    }
    #[test]
    fn rejects_unbound_duplicate_missing_and_malformed_signature_responses() {
        let request = request();
        for response in [
            serde_json::json!({"version":2,"signatures":[]}),
            serde_json::json!({"version":1,"signatures":[]}),
            serde_json::json!({"version":1,"signatures":[{"path":path(),"signature":"key:YWJj"}]}),
            serde_json::json!({"version":1,"signatures":[{"path":"/nix/store/foreign","signature":"key:YWJj"}]}),
        ] {
            assert!(signatures(&request, response.to_string().as_bytes()).is_err());
        }
    }
    #[test]
    fn rejects_noncanonical_metadata() {
        for input in [
            serde_json::json!({path():{"narHash":"sha512-wrong", "narSize":13, "references":[]}}),
            serde_json::json!({path():{"narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize":0, "references":[]}}),
            serde_json::json!({path():{"narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize":13, "references":[path(),path()]}}),
        ] {
            assert!(manifest(input.to_string().as_bytes()).is_err());
        }
    }
    #[test]
    fn metadata_only_cache_imports_real_nix_signature_and_verifies() {
        let nix = std::env::var("NIX_UPDATE_TEST_NIX").unwrap_or_else(|_| "nix".into());
        let temp = std::env::temp_dir().join(format!(
            "native-signing-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&temp).unwrap();
        struct Guard(std::path::PathBuf);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _guard = Guard(temp.clone());
        let source = format!("local?root={}", temp.join("source").display());
        let destination = format!("local?root={}", temp.join("destination").display());
        let run = |store: &str, arguments: &[&str]| {
            let output = Command::new(&nix)
                .args([
                    "--extra-experimental-features",
                    "nix-command",
                    "--option",
                    "build-users-group",
                    "",
                    "--store",
                    store,
                ])
                .args(arguments)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "Nix {:?}: {}",
                arguments,
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        let fixture = temp.join("fixture");
        fs::write(
            &fixture,
            b"public immutable signing interoperability fixture",
        )
        .unwrap();
        let fixture = fixture.to_str().unwrap();
        let path = run(
            &source,
            &[
                "store",
                "add-path",
                "--name",
                "native-signing-test",
                fixture,
            ],
        )
        .trim()
        .to_owned();
        assert_eq!(
            run(
                &destination,
                &[
                    "store",
                    "add-path",
                    "--name",
                    "native-signing-test",
                    fixture
                ]
            )
            .trim(),
            path
        );
        let key = run(
            &source,
            &[
                "key",
                "generate-secret",
                "--key-name",
                "native-signing-test",
            ],
        );
        let key_file = temp.join("ephemeral-key");
        fs::write(&key_file, key).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        let public = {
            use std::io::Write;
            use std::process::Stdio;
            let mut child = Command::new(&nix)
                .args([
                    "--extra-experimental-features",
                    "nix-command",
                    "key",
                    "convert-secret-to-public",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&fs::read(&key_file).unwrap())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        };
        run(
            &source,
            &[
                "store",
                "sign",
                "--key-file",
                key_file.to_str().unwrap(),
                &path,
            ],
        );
        let output = run(&source, &["path-info", "--json", &path]);
        let request = manifest(output.as_bytes()).unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&output).unwrap();
        let signature = metadata[&path]["signatures"][0].as_str().unwrap();
        let cache = temp.join("cache");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("nix-cache-info"), "StoreDir: /nix/store\n").unwrap();
        let basename = path
            .strip_prefix("/nix/store/")
            .unwrap()
            .split_once('-')
            .unwrap()
            .0;
        fs::write(
            cache.join(format!("{basename}.narinfo")),
            narinfo(&request.paths[0], signature),
        )
        .unwrap();
        run(
            &destination,
            &[
                "store",
                "copy-sigs",
                "--substituter",
                &format!("file://{}", cache.display()),
                &path,
            ],
        );
        run(
            &destination,
            &[
                "store",
                "verify",
                "--no-contents",
                "--sigs-needed",
                "1",
                "--option",
                "trusted-public-keys",
                public.trim(),
                &path,
            ],
        );
        assert_eq!(
            fs::read_dir(cache.join("nar")).unwrap().count(),
            0,
            "signature cache must contain no NAR"
        );
    }
}
