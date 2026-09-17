use crate::signing;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const TRUST_VERSION: &str = "AKE-TRUST-1";
const POLICY_VERSION: &str = "AKE-POLICY-1";
const REQUIRE_TRUSTED: &str = "require-trusted";
const ALLOW_UNSIGNED: &str = "allow-unsigned";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Repository,
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub key_id: String,
    pub name: String,
    pub path: PathBuf,
}

fn storage_root() -> PathBuf {
    if let Ok(value) = env::var("AKE_ROOT") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\AKE")
    } else {
        PathBuf::from("/var/lib/ake")
    }
}

fn trust_root() -> PathBuf {
    storage_root().join("security").join("trust")
}

fn keys_root() -> PathBuf {
    trust_root().join("keys")
}

fn records_path() -> PathBuf {
    trust_root().join("trusted.ake-trust")
}

fn policy_path() -> PathBuf {
    trust_root().join("policy.ake")
}

fn valid_hex_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'|' => out.push_str("\\p"),
            _ => out.push(b as char),
        }
    }
    out
}

fn unescape_text(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            return Err("invalid escape in trust database".to_string());
        }
        match bytes[i] {
            b'\\' => out.push(b'\\'),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b'p' => out.push(b'|'),
            _ => return Err("unknown escape in trust database".to_string()),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| "trust database is not UTF-8".to_string())
}

fn read_records() -> Result<Vec<TrustedKey>, String> {
    let path = records_path();
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("cannot read trust database: {e}"))?;
    let mut out = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line_no == 0 {
            if line != TRUST_VERSION {
                return Err("unsupported trust database version".to_string());
            }
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("key=") else {
            return Err(format!("malformed trust database line {}", line_no + 1));
        };
        let mut parts = rest.split('|');
        let key_id = parts.next().ok_or("missing key id")?.to_string();
        let name_raw = parts.next().ok_or("missing trusted key name")?;
        let file_raw = parts.next().ok_or("missing trusted key file")?;
        if parts.next().is_some() || !valid_hex_id(&key_id) {
            return Err(format!("invalid trusted key record on line {}", line_no + 1));
        }
        let name = unescape_text(name_raw)?;
        let filename = unescape_text(file_raw)?;
        if filename != format!("{key_id}.akepub") {
            return Err(format!("invalid trusted key filename for {key_id}"));
        }
        out.push(TrustedKey { key_id: key_id.to_ascii_lowercase(), name, path: keys_root().join(filename) });
    }
    out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(out)
}

fn write_records(records: &[TrustedKey]) -> Result<(), String> {
    fs::create_dir_all(keys_root()).map_err(|e| format!("cannot create trust store: {e}"))?;
    fs::create_dir_all(trust_root()).map_err(|e| format!("cannot create trust store: {e}"))?;
    let path = records_path();
    let tmp = trust_root().join(format!("trusted.ake-trust.tmp.{}", std::process::id()));
    let mut content = format!("{TRUST_VERSION}\n");
    let mut sorted = records.to_vec();
    sorted.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    for item in sorted {
        content.push_str("key=");
        content.push_str(&item.key_id);
        content.push('|');
        content.push_str(&escape_text(&item.name));
        content.push('|');
        content.push_str(&escape_text(&format!("{}.akepub", item.key_id)));
        content.push('\n');
    }
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)
            .map_err(|e| format!("cannot create trust database transaction: {e}"))?;
        file.write_all(content.as_bytes()).map_err(|e| format!("cannot write trust database: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot flush trust database: {e}"))?;
        drop(file);
        if path.is_file() {
            let backup = trust_root().join(format!("trusted.ake-trust.old.{}", std::process::id()));
            fs::rename(&path, &backup).map_err(|e| format!("cannot stage old trust database: {e}"))?;
            if let Err(e) = fs::rename(&tmp, &path) {
                let _ = fs::rename(&backup, &path);
                return Err(format!("cannot commit trust database: {e}"));
            }
            let _ = fs::remove_file(backup);
        } else {
            fs::rename(&tmp, &path).map_err(|e| format!("cannot commit trust database: {e}"))?;
        }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}

pub fn add(public_key_path: &str, name: Option<&str>) -> Result<String, String> {
    let source = Path::new(public_key_path);
    let bytes = fs::read(source).map_err(|e| format!("cannot read public key: {e}"))?;
    if bytes.len() != 72 || &bytes[0..4] != b"ECK1" || u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != 32 {
        return Err("invalid Windows CNG ECDSA P-256 public key blob".to_string());
    }
    let key_id = signing::key_id_for_public_key(&bytes);
    let mut records = read_records()?;
    if let Some(existing) = records.iter().find(|r| r.key_id == key_id) {
        return Err(format!("key is already trusted: {} ({})", existing.key_id, existing.name));
    }
    fs::create_dir_all(keys_root()).map_err(|e| format!("cannot create trust store: {e}"))?;
    let target = keys_root().join(format!("{key_id}.akepub"));
    let tmp = keys_root().join(format!("{key_id}.akepub.tmp.{}", std::process::id()));
    fs::write(&tmp, &bytes).map_err(|e| format!("cannot write trusted public key: {e}"))?;
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot install trusted public key: {e}"));
    }
    let display_name = match name {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => key_id.clone(),
    };
    if display_name.len() > 160 || display_name.contains('\0') {
        let _ = fs::remove_file(&target);
        return Err("trusted key name is invalid or too long".to_string());
    }
    records.push(TrustedKey { key_id: key_id.clone(), name: display_name, path: target.clone() });
    if let Err(e) = write_records(&records) {
        let _ = fs::remove_file(&target);
        return Err(e);
    }
    Ok(key_id)
}

pub fn remove(key_id: &str) -> Result<(), String> {
    let normalized = key_id.to_ascii_lowercase();
    if !valid_hex_id(&normalized) {
        return Err("invalid key id".to_string());
    }
    let mut records = read_records()?;
    let before = records.len();
    let removed = records.iter().find(|r| r.key_id == normalized).cloned();
    if removed.is_none() {
        return Err(format!("trusted key not found: {normalized}"));
    }
    records.retain(|r| r.key_id != normalized);
    write_records(&records)?;
    if let Some(item) = removed {
        let _ = fs::remove_file(item.path);
    }
    if before == records.len() {
        return Err("trusted key removal did not change the trust store".to_string());
    }
    Ok(())
}

pub fn list() -> Result<Vec<TrustedKey>, String> {
    read_records()
}

fn default_policy(source: Source) -> &'static str {
    match source {
        Source::Local => ALLOW_UNSIGNED,
        Source::Repository => REQUIRE_TRUSTED,
    }
}

fn validate_policy(value: &str) -> bool {
    value == ALLOW_UNSIGNED || value == REQUIRE_TRUSTED
}

fn read_policy() -> Result<(String, String), String> {
    let path = policy_path();
    if !path.is_file() {
        return Ok((default_policy(Source::Local).to_string(), default_policy(Source::Repository).to_string()));
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("cannot read AKE trust policy: {e}"))?;
    let mut local = default_policy(Source::Local).to_string();
    let mut repository = default_policy(Source::Repository).to_string();
    for (line_no, line) in text.lines().enumerate() {
        if line_no == 0 {
            if line != POLICY_VERSION { return Err("unsupported AKE policy version".to_string()); }
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') { continue; }
        let Some((key, value)) = line.split_once('=') else { return Err(format!("malformed policy line {}", line_no + 1)); };
        if !validate_policy(value) { return Err(format!("invalid policy value on line {}", line_no + 1)); }
        match key {
            "local" => local = value.to_string(),
            "repository" => repository = value.to_string(),
            _ => return Err(format!("unknown policy field: {key}")),
        }
    }
    Ok((local, repository))
}

pub fn policy() -> Result<(String, String), String> {
    read_policy()
}

pub fn set_policy(scope: &str, value: &str) -> Result<(), String> {
    if scope != "local" && scope != "repository" { return Err("policy scope must be local or repository".to_string()); }
    if !validate_policy(value) { return Err("policy must be allow-unsigned or require-trusted".to_string()); }
    let (mut local, mut repository) = read_policy()?;
    if scope == "local" { local = value.to_string(); } else { repository = value.to_string(); }
    fs::create_dir_all(&trust_root()).map_err(|e| format!("cannot create trust store: {e}"))?;
    let path = policy_path();
    let tmp = trust_root().join(format!("policy.ake.tmp.{}", std::process::id()));
    let content = format!("{POLICY_VERSION}\nlocal={local}\nrepository={repository}\n");
    fs::write(&tmp, content.as_bytes()).map_err(|e| format!("cannot write AKE policy: {e}"))?;
    if path.is_file() {
        let backup = trust_root().join(format!("policy.ake.old.{}", std::process::id()));
        if let Err(e) = fs::rename(&path, &backup) {
            let _ = fs::remove_file(&tmp);
            return Err(format!("cannot stage old AKE policy: {e}"));
        }
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::rename(&backup, &path);
            let _ = fs::remove_file(&tmp);
            return Err(format!("cannot commit AKE policy: {e}"));
        }
        let _ = fs::remove_file(&backup);
    } else if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot commit AKE policy: {e}"));
    }
    Ok(())
}

fn signature_path(package: &Path) -> PathBuf {
    let mut value = package.as_os_str().to_owned();
    value.push(".sig");
    PathBuf::from(value)
}

pub fn verify_trusted(package: &str, signature: Option<&str>) -> Result<String, String> {
    let package_path = Path::new(package);
    let sig_path = PathBuf::from(signature.map(PathBuf::from).unwrap_or_else(|| signature_path(package_path)));
    let parsed = signing::read_signature(package_path, &sig_path)?;
    let trusted = read_records()?;
    let signer = trusted.iter().find(|key| key.key_id.eq_ignore_ascii_case(&parsed.key_id));
    let Some(signer) = signer else {
        return Err(format!("signature key is not trusted: {}", parsed.key_id));
    };
    let trusted_public = fs::read(&signer.path).map_err(|e| format!("cannot read trusted public key: {e}"))?;
    if trusted_public != parsed.public_key {
        return Err("signature public key does not match the trusted key record".to_string());
    }
    signing::verify_digest_with_public_key(package_path, &parsed, &trusted_public)?;
    Ok(format!("{} ({})", signer.name, signer.key_id))
}

pub fn enforce_install_policy(package: &str, source: Source) -> Result<Option<String>, String> {
    let package_path = Path::new(package);
    let (local_policy, repository_policy) = read_policy()?;
    let selected = match source {
        Source::Local => local_policy,
        Source::Repository => repository_policy,
    };
    let sig_path = signature_path(package_path);
    if sig_path.is_file() {
        return verify_trusted(package, Some(sig_path.to_string_lossy().as_ref())).map(Some);
    }
    if selected == REQUIRE_TRUSTED {
        return Err(format!("trusted signature required by {} package policy", match source { Source::Local => "local", Source::Repository => "repository" }));
    }
    Ok(None)
}

pub fn root() -> PathBuf {
    trust_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_are_distinct() {
        assert_eq!(default_policy(Source::Local), ALLOW_UNSIGNED);
        assert_eq!(default_policy(Source::Repository), REQUIRE_TRUSTED);
    }

    #[test]
    fn key_ids_are_64_hex_characters() {
        let id = signing::key_id_for_public_key(&[0x41; 64]);
        assert_eq!(id.len(), 64);
        assert!(valid_hex_id(&id));
    }
}
