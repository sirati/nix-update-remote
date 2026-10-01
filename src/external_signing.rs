//! Bounded, dependency-independent artifact signing command protocol.
use crate::cancellation::ManagedCommand;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};
const LIMIT: usize = 65536;
#[derive(Serialize)]
struct Manifest {
    artifacts: Vec<Artifact>,
}
#[derive(Serialize)]
struct Artifact {
    role: String,
    path: String,
    sha512: String,
    size: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    signatures: Vec<Signature>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    role: String,
    sha512: String,
    size: u64,
    signature_base64: String,
}
fn decode(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() % 4 != 0 || text.len() > 22000 {
        return Err("invalid signature encoding length".into());
    }
    let value = |c| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    for (i, chunk) in text.as_bytes().chunks_exact(4).enumerate() {
        let a = value(chunk[0]).ok_or("invalid base64")?;
        let b = value(chunk[1]).ok_or("invalid base64")?;
        let last = (i + 1) * 4 == text.len();
        out.push((a << 2) | (b >> 4));
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 15 != 0 {
                return Err("invalid base64 padding".into());
            }
        } else {
            let c = value(chunk[2]).ok_or("invalid base64")?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] == b'=' {
                if !last || c & 3 != 0 {
                    return Err("invalid base64 padding".into());
                }
            } else {
                out.push((c << 6) | value(chunk[3]).ok_or("invalid base64")?);
            }
        }
    }
    Ok(out)
}
fn validate(manifest: &Manifest, bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let response: Response =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid signing response: {e}"))?;
    if response.signatures.len() != manifest.artifacts.len() {
        return Err("signing response artifact count differs".into());
    }
    let mut result = BTreeMap::new();
    for signature in response.signatures {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|a| a.role == signature.role)
            .ok_or("unexpected signature role")?;
        if signature.sha512 != artifact.sha512 || signature.size != artifact.size {
            return Err("signature artifact binding differs".into());
        }
        let decoded = decode(&signature.signature_base64)?;
        if result.insert(signature.role, decoded).is_some() {
            return Err("duplicate signature role".into());
        }
    }
    Ok(result)
}
fn exchange(command: &str, args: &[String], input: Vec<u8>) -> Result<Vec<u8>, String> {
    if input.len() > LIMIT {
        return Err("signing manifest exceeds limit".into());
    }
    // A small explicit pipe bounds transport buffering independently of the
    // host's pipe defaults; the writer remains concurrent with the response.
    let (input_read, input_write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| e.to_string())?;
    rustix::pipe::fcntl_setpipe_size(&input_write, 4096).map_err(|e| e.to_string())?;
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::from(input_read))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .managed_spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = fs::File::from(input_write);
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut stdout = child.stdout.take().ok_or("missing signing stdout")?;
    let mut output = Vec::new();
    let read = stdout
        .by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut output);
    if read.is_err() || output.len() > LIMIT {
        let _ = child.kill();
    }
    drop(stdout);
    let status = child.wait().map_err(|e| e.to_string());
    let written = writer.join().map_err(|_| "signing input thread failed")?;
    let status = status?;
    read.map_err(|e| e.to_string())?;
    if output.len() > LIMIT {
        return Err("signing response exceeds limit".into());
    }
    if !status.success() {
        return Err(format!("external signing command failed: {status}"));
    }
    written.map_err(|e| format!("sending signing manifest failed: {e}"))?;
    Ok(output)
}
pub fn sign(
    command: &str,
    args: &[String],
    hash: &Path,
    directory: &Path,
    definitions: &[(&str, &str, &str)],
) -> Result<(), String> {
    let mut manifest = Manifest {
        artifacts: Vec::new(),
    };
    for (_, name, role) in definitions {
        let staged = directory.join(name);
        if !staged.exists() {
            continue;
        }
        let path = fs::canonicalize(&staged).map_err(|e| e.to_string())?;
        let output = Command::new(hash)
            .arg(&path)
            .managed_output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("hashing signing artifact failed".into());
        }
        let digest = std::str::from_utf8(&output.stdout)
            .map_err(|e| e.to_string())?
            .split_whitespace()
            .next()
            .ok_or("missing artifact digest")?
            .to_owned();
        if digest.len() != 128
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid artifact SHA512 digest".into());
        }
        manifest.artifacts.push(Artifact {
            role: (*role).into(),
            path: path.to_str().ok_or("non UTF8 artifact path")?.into(),
            sha512: digest,
            size: fs::metadata(path).map_err(|e| e.to_string())?.len(),
        });
    }
    let input = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let response = exchange(command, args, input)?;
    let signatures = validate(&manifest, &response)?;
    for (_, name, role) in definitions {
        if let Some(signature) = signatures.get(*role) {
            fs::write(directory.join(format!("{name}.sig")), signature)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest {
            artifacts: vec![Artifact {
                role: "generation-image".into(),
                path: "/nix/store/example".into(),
                sha512: "a".repeat(128),
                size: 42,
            }],
        }
    }
    fn response() -> serde_json::Value {
        serde_json::json!({"signatures":[{"role":"generation-image","sha512":"a".repeat(128),"size":42,"signature_base64":"YWJj"}]})
    }
    #[test]
    fn bindings_are_exact() {
        let m = manifest();
        assert_eq!(
            validate(&m, &serde_json::to_vec(&response()).unwrap()).unwrap()["generation-image"],
            b"abc"
        );
        for field in ["role", "sha512", "size"] {
            let mut r = response();
            r["signatures"][0][field] = if field == "size" {
                serde_json::json!(43)
            } else {
                serde_json::json!("wrong")
            };
            assert!(validate(&m, &serde_json::to_vec(&r).unwrap()).is_err());
        }
        assert!(validate(&m, br#"{"signatures":[]}"#).is_err());
        let mut r = response();
        let duplicate = r["signatures"][0].clone();
        r["signatures"].as_array_mut().unwrap().push(duplicate);
        assert!(validate(&m, &serde_json::to_vec(&r).unwrap()).is_err());
        for bad in ["", "YQ=A", "YR==", "YWJ=", "YWJj====", "!!!!"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
        assert_eq!(decode("YQ==").unwrap(), b"a");
        assert_eq!(decode("YWI=").unwrap(), b"ab");
    }
    #[test]
    fn duplicate_and_extra_roles_are_rejected_with_same_count() {
        let mut m = manifest();
        m.artifacts.push(Artifact {
            role: "boot-config".into(),
            path: "/nix/store/second".into(),
            sha512: "b".repeat(128),
            size: 7,
        });
        let mut r = response();
        let duplicate = r["signatures"][0].clone();
        r["signatures"].as_array_mut().unwrap().push(duplicate);
        assert!(
            validate(&m, &serde_json::to_vec(&r).unwrap())
                .unwrap_err()
                .contains("duplicate")
        );
        r["signatures"][1]["role"] = serde_json::json!("unknown");
        assert!(
            validate(&m, &serde_json::to_vec(&r).unwrap())
                .unwrap_err()
                .contains("unexpected")
        );
    }
    #[test]
    fn signing_modes_are_exclusive_before_upload() {
        for flags in [
            vec!["--signing-key", "/missing", "--sign-command", "cat"],
            vec!["--key-command", "cat", "--sign-command", "cat"],
            vec![],
        ] {
            let args = [vec!["--target", "update@localhost"], flags]
                .concat()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert!(
                crate::artifact_client::deploy(&args)
                    .unwrap_err()
                    .contains("exactly one")
            );
        }
    }
    #[test]
    fn real_child_exchange_and_failure() {
        assert_eq!(
            exchange("cat", &[], b"bounded manifest".to_vec()).unwrap(),
            b"bounded manifest"
        );
        assert!(exchange("false", &[], b"manifest".to_vec()).is_err());
        assert!(
            exchange(
                "head",
                &["-c".into(), "65537".into(), "/dev/zero".into()],
                b"manifest".to_vec()
            )
            .unwrap_err()
            .contains("limit")
        );
    }
}
