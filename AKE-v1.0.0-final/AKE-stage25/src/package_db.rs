use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DB_VERSION: &str = "AKE-DB-1";

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub id: String,
    pub version: String,
    pub architecture: String,
    pub name: String,
    pub entry: String,
    pub dependencies: Vec<(String, String)>,
    pub install_dir: PathBuf,
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

fn db_dir() -> PathBuf {
    storage_root().join("database").join("installed")
}

fn package_root() -> PathBuf {
    storage_root().join("packages")
}

fn encode_component(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        let safe = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-');
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
            out.push(char::from(b"0123456789ABCDEF"[(b & 0x0f) as usize]));
        }
    }
    if out.is_empty() || out.len() > 180 {
        return Err("package identity component is empty or too long".to_string());
    }
    Ok(out)
}

fn record_dir(id: &str) -> Result<PathBuf, String> {
    Ok(db_dir().join(encode_component(id)?))
}

fn install_dir(id: &str, version: &str) -> Result<PathBuf, String> {
    Ok(package_root().join(encode_component(id)?).join(encode_component(version)?))
}

fn write_record(path: &Path, pkg: &InstalledPackage) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "invalid package database path".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create package database: {e}"))?;
    let temp = parent.join(format!("record.tmp.{}.{}", std::process::id(), timestamp_seed()));
    let mut content = format!(
        "{DB_VERSION}\nid={id}\nversion={version}\narchitecture={architecture}\nname={name}\nentry={entry}\n",
        id = escape_field(&pkg.id),
        version = escape_field(&pkg.version),
        architecture = escape_field(&pkg.architecture),
        name = escape_field(&pkg.name),
        entry = escape_field(&pkg.entry),
    );
    for (dep_id, constraint) in &pkg.dependencies {
        content.push_str("dependency=");
        content.push_str(&escape_field(dep_id));
        content.push_str("|");
        content.push_str(&escape_field(constraint));
        content.push('\n');
    }
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)
            .map_err(|e| format!("cannot create package database record: {e}"))?;
        file.write_all(content.as_bytes()).map_err(|e| format!("cannot write package database record: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot flush package database record: {e}"))?;
        drop(file);
        fs::rename(&temp, path).map_err(|e| format!("cannot commit package database record: {e}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}



fn write_record_temp(path: &Path, pkg: &InstalledPackage) -> Result<PathBuf, String> {
    let parent = path.parent().ok_or_else(|| "invalid package database path".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create package database: {e}"))?;
    let temp = parent.join(format!("record.new.{}.{}", std::process::id(), timestamp_seed()));
    let mut content = format!(
        "{DB_VERSION}\nid={id}\nversion={version}\narchitecture={architecture}\nname={name}\nentry={entry}\n",
        id = escape_field(&pkg.id),
        version = escape_field(&pkg.version),
        architecture = escape_field(&pkg.architecture),
        name = escape_field(&pkg.name),
        entry = escape_field(&pkg.entry),
    );
    for (dep_id, constraint) in &pkg.dependencies {
        content.push_str("dependency=");
        content.push_str(&escape_field(dep_id));
        content.push_str("|");
        content.push_str(&escape_field(constraint));
        content.push('\n');
    }
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)
            .map_err(|e| format!("cannot create package database transaction record: {e}"))?;
        file.write_all(content.as_bytes()).map_err(|e| format!("cannot write package database transaction record: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot flush package database transaction record: {e}"))?;
        Ok(temp.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn swap_record(record_path: &Path, new_record: &Path) -> Result<PathBuf, String> {
    let parent = record_path.parent().ok_or_else(|| "invalid package database record path".to_string())?;
    let backup = parent.join(format!("record.old.{}.{}", std::process::id(), timestamp_seed()));
    if record_path.is_file() {
        fs::rename(record_path, &backup)
            .map_err(|e| format!("cannot stage old package database record for update: {e}"))?;
    }
    if let Err(e) = fs::rename(new_record, record_path) {
        if backup.is_file() {
            let _ = fs::rename(&backup, record_path);
        }
        return Err(format!("cannot commit package database update: {e}"));
    }
    Ok(backup)
}

fn restore_record(record_path: &Path, backup: &Path) -> Result<(), String> {
    if record_path.exists() {
        let _ = fs::remove_file(record_path);
    }
    if backup.is_file() {
        fs::rename(backup, record_path)
            .map_err(|e| format!("cannot restore package database record: {e}"))?;
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<InstalledPackage, String> {
    let mut file = File::open(path).map_err(|e| format!("cannot open package database record: {e}"))?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| format!("cannot read package database record: {e}"))?;
    let mut fields = std::collections::BTreeMap::new();
    for (line_no, line) in text.lines().enumerate() {
        if line_no == 0 {
            if line != DB_VERSION { return Err("unsupported package database version".to_string()); }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err("malformed package database record".to_string());
        };
        let decoded = unescape_field(value)?;
        if key == "dependency" {
            fields.entry(key.to_string()).and_modify(|existing| {
                existing.push('\n');
                existing.push_str(&decoded);
            }).or_insert(decoded);
        } else {
            fields.insert(key.to_string(), decoded);
        }
    }
    let id = required(&fields, "id")?;
    let version = required(&fields, "version")?;
    let architecture = required(&fields, "architecture")?;
    let name = required(&fields, "name")?;
    let entry = required(&fields, "entry")?;
    let mut dependencies = Vec::new();
    for raw in fields.get("dependency").into_iter().flat_map(|v| v.split('\n')) {
        let (dep_id, constraint) = raw.split_once('|')
            .ok_or_else(|| "malformed package database dependency record".to_string())?;
        dependencies.push((dep_id.to_string(), constraint.to_string()));
    }
    let dir = install_dir(&id, &version)?;
    Ok(InstalledPackage { id, version, architecture, name, entry, dependencies, install_dir: dir })
}

fn required(fields: &std::collections::BTreeMap<String, String>, key: &str) -> Result<String, String> {
    fields.get(key).cloned().ok_or_else(|| format!("package database record is missing {key}"))
}

fn escape_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.as_bytes() {
        match *b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'=' => out.push_str("\\e"),
            _ => out.push(*b as char),
        }
    }
    out
}

fn unescape_field(value: &str) -> Result<String, String> {
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
        if i >= bytes.len() { return Err("invalid escape in package database record".to_string()); }
        match bytes[i] {
            b'\\' => out.push(b'\\'),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b'e' => out.push(b'='),
            _ => return Err("unknown escape in package database record".to_string()),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| "package database record is not UTF-8".to_string())
}

fn timestamp_seed() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos()
}

pub fn install<F>(id: &str, version: &str, architecture: &str, name: &str, entry: &str, dependencies: &[(String, String)], extract: F) -> Result<InstalledPackage, String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let record = record_dir(id)?;
    if record.exists() {
        return Err(format!("package {id} is already installed"));
    }
    let final_dir = install_dir(id, version)?;
    if final_dir.exists() {
        return Err("installation destination already exists".to_string());
    }
    let id_root = final_dir.parent().ok_or_else(|| "invalid installation path".to_string())?;
    fs::create_dir_all(id_root).map_err(|e| format!("cannot create package directory: {e}"))?;

    let staging = id_root.join(format!(".stage-{}-{}", std::process::id(), timestamp_seed()));
    if staging.exists() { return Err("installation staging directory already exists".to_string()); }

    if let Err(e) = extract(&staging) {
        let _ = fs::remove_dir_all(&staging);
        let _ = cleanup_empty_parent(id_root);
        return Err(e);
    }

    if let Err(e) = fs::rename(&staging, &final_dir) {
        let _ = fs::remove_dir_all(&staging);
        let _ = cleanup_empty_parent(id_root);
        return Err(format!("cannot commit installation: {e}"));
    }

    let pkg = InstalledPackage {
        id: id.to_string(),
        version: version.to_string(),
        architecture: architecture.to_string(),
        name: name.to_string(),
        entry: entry.to_string(),
        dependencies: dependencies.to_vec(),
        install_dir: final_dir.clone(),
    };

    if let Err(e) = write_record(&record.join("record.db"), &pkg) {
        let _ = fs::remove_dir_all(&final_dir);
        let _ = cleanup_empty_parent(id_root);
        return Err(e);
    }

    Ok(pkg)
}



pub fn update<F>(
    id: &str,
    version: &str,
    architecture: &str,
    name: &str,
    entry: &str,
    dependencies: &[(String, String)],
    extract: F,
) -> Result<(InstalledPackage, InstalledPackage, bool), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let old = find(id)?;
    if old.version == version {
        return Err(format!("package {id} is already at version {version}"));
    }

    let record_path = record_dir(id)?.join("record.db");
    let final_dir = install_dir(id, version)?;
    if final_dir.exists() {
        return Err("target package version directory already exists".to_string());
    }

    let package_parent = final_dir.parent().ok_or_else(|| "invalid installation path".to_string())?;
    fs::create_dir_all(package_parent).map_err(|e| format!("cannot create package directory: {e}"))?;

    let staging = package_parent.join(format!(".update-stage-{}-{}", std::process::id(), timestamp_seed()));
    if staging.exists() {
        return Err("update staging directory already exists".to_string());
    }

    if let Err(e) = extract(&staging) {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }

    let new_pkg = InstalledPackage {
        id: id.to_string(),
        version: version.to_string(),
        architecture: architecture.to_string(),
        name: name.to_string(),
        entry: entry.to_string(),
        dependencies: dependencies.to_vec(),
        install_dir: final_dir.clone(),
    };

    let package_root_path = package_root().canonicalize()
        .map_err(|e| format!("cannot resolve package root: {e}"))?;
    let old_dir = old.install_dir.canonicalize()
        .map_err(|e| format!("old installed package directory is missing: {e}"))?;
    if !old_dir.starts_with(&package_root_path) || !old_dir.is_dir() {
        let _ = fs::remove_dir_all(&staging);
        return Err("refusing to update an old package path outside AKE package root".to_string());
    }

    let new_record = match write_record_temp(&record_path, &new_pkg) {
        Ok(path) => path,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    // Commit the new files before replacing the database record. If the
    // database swap fails, the new tree is removed and the old package stays
    // the active installation.
    if let Err(e) = fs::rename(&staging, &final_dir) {
        let _ = fs::remove_file(&new_record);
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("cannot commit new package version: {e}"));
    }

    let old_record_backup = match swap_record(&record_path, &new_record) {
        Ok(backup) => backup,
        Err(e) => {
            let _ = fs::remove_dir_all(&final_dir);
            let _ = fs::remove_file(&new_record);
            return Err(e);
        }
    };

    // Removing the old version is deliberately last. A locked old executable
    // on Windows must not make the newly committed version disappear.
    let stale_old = if let Err(_e) = fs::remove_dir_all(&old_dir) {
        true
    } else {
        let _ = cleanup_empty_parent(old_dir.parent().unwrap_or(package_parent));
        false
    };

    let _ = fs::remove_file(&old_record_backup);
    Ok((old, new_pkg, stale_old))
}

pub fn find(id: &str) -> Result<InstalledPackage, String> {
    let record = record_dir(id)?.join("record.db");
    if !record.is_file() {
        return Err(format!("package {id} is not installed"));
    }
    read_record(&record)
}

pub fn remove(id: &str) -> Result<InstalledPackage, String> {
    let pkg = find(id)?;
    let root = package_root().canonicalize().map_err(|e| format!("cannot resolve package root: {e}"))?;
    let target = pkg.install_dir.canonicalize().map_err(|e| format!("installed package directory is missing: {e}"))?;
    if !target.starts_with(&root) {
        return Err("refusing to remove path outside AKE package root".to_string());
    }
    fs::remove_dir_all(&target).map_err(|e| format!("cannot remove installed package: {e}"))?;
    let record_parent = record_dir(id)?;
    fs::remove_dir_all(&record_parent).map_err(|e| format!("cannot remove package database record: {e}"))?;
    let _ = cleanup_empty_parent(&target);
    Ok(pkg)
}

pub fn list() -> Result<Vec<InstalledPackage>, String> {
    let dir = db_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir).map_err(|e| format!("cannot read package database: {e}"))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read package database entry: {e}"))?;
        let path = entry.path().join("record.db");
        if path.is_file() {
            out.push(read_record(&path)?);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.version.cmp(&b.version)));
    Ok(out)
}

pub fn root() -> PathBuf {
    storage_root()
}

fn cleanup_empty_parent(path: &Path) -> io::Result<()> {
    match fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_none() {
                fs::remove_dir(path)?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_encoding_is_safe_and_deterministic() {
        let value = "com.example/app v1";
        let encoded = encode_component(value).unwrap();
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains(' '));
        assert_eq!(encoded, "com.example%2Fapp%20v1");
    }

    #[test]
    fn field_escape_roundtrip() {
        let original = "a=b\\c\nnext\rline";
        assert_eq!(unescape_field(&escape_field(original)).unwrap(), original);
    }

    #[test]
    fn dependency_records_roundtrip() {
        let pkg = InstalledPackage {
            id: "com.example.app".to_string(),
            version: "1.0.0".to_string(),
            architecture: "x64".to_string(),
            name: "Example".to_string(),
            entry: "bin/Example.exe".to_string(),
            dependencies: vec![("runtime".to_string(), ">=2.0.0".to_string()), ("tools".to_string(), "=3.0.0".to_string())],
            install_dir: PathBuf::from("C:/unused"),
        };
        let encoded = pkg.dependencies.iter().map(|(a,b)| format!("{}|{}", escape_field(a), escape_field(b))).collect::<Vec<_>>().join("\n");
        let raw = encoded.lines().map(|v| {
            let (a,b) = v.split_once('|').unwrap();
            (unescape_field(a).unwrap(), unescape_field(b).unwrap())
        }).collect::<Vec<_>>();
        assert_eq!(raw, pkg.dependencies);
    }
}
