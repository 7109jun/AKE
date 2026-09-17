use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::ffi::CString;
use crate::package_db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeSource {
    Named(String),
    Host(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    pub name: String,
    pub source: VolumeSource,
    pub target: String,
    pub read_only: bool,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn normalize_target(value: &str) -> Result<String, String> {
    let raw = value.trim().replace('\\', "/");
    if raw.is_empty() || raw.starts_with('/') || raw.contains(':') || raw == "." || raw.contains("//") {
        return Err(format!("invalid volume target: {value}"));
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." { continue; }
        if part == ".." { return Err("volume target cannot escape package root".to_string()); }
        if part.bytes().any(|b| b < 0x20 || b == b'\0') { return Err("volume target contains control characters".to_string()); }
        parts.push(part);
    }
    let target = parts.join("/");
    if target.is_empty() || target == "bin" || target == "config" || target == "lib" || target == "metadata" || target == "data" {
        return Err("volume target must be below data/ and cannot replace a package root directory".to_string());
    }
    if !target.starts_with("data/") {
        return Err("AKE v1.0 volumes must target a path below data/".to_string());
    }
    Ok(target)
}

fn parse_name_tail(key: &str, suffix: &str) -> Option<String> {
    key.strip_prefix("volume.")?.strip_suffix(suffix).map(|v| v.to_string())
}

pub fn parse_specs(info: &str) -> Result<Vec<VolumeSpec>, String> {
    let mut names = Vec::<String>::new();
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("volume.") {
            if let Some((name, field)) = rest.split_once('.') {
                if matches!(field, "source" | "target" | "mode") {
                    if !valid_name(name) { return Err(format!("invalid volume name: {name}")); }
                    if !names.iter().any(|n| n == name) { names.push(name.to_string()); }
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut targets = Vec::<String>::new();
    let mut env_keys = Vec::<String>::new();
    for name in names {
        let source_key = format!("volume.{name}.source");
        let target_key = format!("volume.{name}.target");
        let mode_key = format!("volume.{name}.mode");
        let source_raw = info.lines().find_map(|l| l.strip_prefix(&source_key).and_then(|v| v.strip_prefix('='))).ok_or_else(|| format!("volume {name} is missing source"))?;
        let target_raw = info.lines().find_map(|l| l.strip_prefix(&target_key).and_then(|v| v.strip_prefix('='))).ok_or_else(|| format!("volume {name} is missing target"))?;
        let mode = info.lines().find_map(|l| l.strip_prefix(&mode_key).and_then(|v| v.strip_prefix('='))).unwrap_or("rw").trim().to_ascii_lowercase();
        let read_only = match mode.as_str() {
            "rw" => false,
            "ro" | "read-only" => true,
            other => return Err(format!("invalid volume mode for {name}: {other}")),
        };
        let target = normalize_target(target_raw)?;
        if targets.iter().any(|t| t == &target) { return Err(format!("duplicate volume target: {target}")); }
        targets.push(target.clone());
        let env_key: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
        if env_keys.iter().any(|k| k == &env_key) {
            return Err(format!("volume names produce a duplicate environment variable: {env_key}"));
        }
        env_keys.push(env_key);
        let source = if let Some(name) = source_raw.strip_prefix('@') {
            if !valid_name(name) { return Err(format!("invalid named volume: {name}")); }
            VolumeSource::Named(name.to_string())
        } else {
            let p = PathBuf::from(source_raw.trim());
            if !p.is_absolute() { return Err(format!("host volume source must be absolute: {source_raw}")); }
            VolumeSource::Host(p)
        };
        out.push(VolumeSpec { name, source, target, read_only });
    }
    out.sort_by(|a,b| a.name.cmp(&b.name));
    Ok(out)
}

fn volume_root() -> PathBuf { package_db::root().join("volumes") }

fn target_path(run_dir: &Path, target: &str) -> PathBuf {
    target.split('/').fold(run_dir.to_path_buf(), |mut path, component| { path.push(component); path })
}
fn volume_path(name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) { return Err("invalid volume name".to_string()); }
    Ok(volume_root().join(name))
}

pub fn create(name: &str) -> Result<PathBuf, String> {
    let path = volume_path(name)?;
    let marker = path.join(".ake-volume");
    if path.exists() {
        if !path.is_dir() || !marker.is_file() {
            return Err(format!("volume path already exists and is not an AKE volume: {}", path.display()));
        }
        return Ok(path);
    }
    fs::create_dir_all(&path).map_err(|e| format!("cannot create volume: {e}"))?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(&marker)
        .map_err(|e| format!("cannot create volume marker: {e}"))?;
    use std::io::Write;
    file.write_all(b"AKE-VOLUME-1\n").map_err(|e| format!("cannot write volume marker: {e}"))?;
    file.sync_all().map_err(|e| format!("cannot flush volume marker: {e}"))?;
    Ok(path)
}

pub fn source_path(source: &VolumeSource) -> Result<PathBuf, String> {
    match source {
        VolumeSource::Named(name) => {
            let path = volume_path(name)?;
            if !path.exists() { create(name)?; }
            Ok(path)
        }
        VolumeSource::Host(path) => {
            if !path.exists() { return Err(format!("host volume source does not exist: {}", path.display())); }
            let canonical = path.canonicalize().map_err(|e| format!("cannot resolve host volume source: {e}"))?;
            if !canonical.is_dir() { return Err(format!("host volume source is not a directory: {}", canonical.display())); }
            Ok(canonical)
        }
    }
}

extern "C" {
    fn ake_mount_volume(source: *const i8, target: *const i8, read_only: i32) -> i32;
}


pub fn bind_directory(source: &Path, target: &Path, read_only: bool) -> Result<(), String> {
    if target.exists() { return Err(format!("volume target already exists: {}", target.display())); }
    if let Some(parent) = target.parent() { fs::create_dir_all(parent).map_err(|e| format!("cannot create volume target parent: {e}"))?; }
    let source = source.canonicalize().map_err(|e| format!("cannot resolve directory source: {e}"))?;
    if !source.is_dir() { return Err(format!("directory source is not a directory: {}", source.display())); }
    let source_c = CString::new(source.to_string_lossy().as_bytes()).map_err(|_| "invalid volume source path".to_string())?;
    let target_c = CString::new(target.to_string_lossy().as_bytes()).map_err(|_| "invalid volume target path".to_string())?;
    let rc = unsafe { ake_mount_volume(source_c.as_ptr(), target_c.as_ptr(), if read_only { 1 } else { 0 }) };
    if rc != 0 { return Err(format!("cannot bind directory {} (code {rc})", source.display())); }
    Ok(())
}

pub fn unmount_directory(target: &Path) -> Result<(), String> {
    let target_c = CString::new(target.to_string_lossy().as_bytes()).map_err(|_| "invalid volume target path".to_string())?;
    let rc = unsafe { ake_unmount_volume(target_c.as_ptr()) };
    if rc != 0 { return Err(format!("cannot unmount directory (code {rc})")); }
    Ok(())
}

pub fn mount_all(specs: &[VolumeSpec], run_dir: &Path) -> Result<Vec<VolumeSpec>, String> {
    let mut mounted = Vec::new();
    let run_root = run_dir.canonicalize().map_err(|e| format!("cannot resolve runtime root: {e}"))?;
    for spec in specs {
        let source = source_path(&spec.source)?;
        let target = target_path(run_dir, &spec.target);
        if target.exists() { return Err(format!("volume target already exists: {}", target.display())); }
        if let Some(parent) = target.parent() { fs::create_dir_all(parent).map_err(|e| format!("cannot create volume target parent: {e}"))?; }
        let source_canon = source.canonicalize().map_err(|e| format!("cannot resolve volume source: {e}"))?;
        if source_canon == run_root || source_canon.starts_with(&run_root) {
            return Err(format!("volume source cannot be inside runtime root: {}", source_canon.display()));
        }
        let source_c = CString::new(source.to_string_lossy().as_bytes()).map_err(|_| "invalid volume source path".to_string())?;
        let target_c = CString::new(target.to_string_lossy().as_bytes()).map_err(|_| "invalid volume target path".to_string())?;
        let rc = unsafe { ake_mount_volume(source_c.as_ptr(), target_c.as_ptr(), if spec.read_only { 1 } else { 0 }) };
        if rc != 0 {
            for prior in mounted.iter().rev() {
                let prior_target = target_path(run_dir, &prior.target);
                let _ = unmount_directory(&prior_target);
            }
            return Err(format!("cannot mount volume {} (code {rc})", spec.name));
        }
        mounted.push(spec.clone());
    }
    Ok(mounted)
}

extern "C" {
    fn ake_unmount_volume(target: *const i8) -> i32;
}

pub fn unmount_all(specs: &[VolumeSpec], run_dir: &Path) -> Result<(), String> {
    let mut first_error = None;
    for spec in specs.iter().rev() {
        let target = target_path(run_dir, &spec.target);
        if target.exists() {
            if let Err(e) = unmount_directory(&target) { if first_error.is_none() { first_error = Some(e); } }
        }
    }
    if let Some(e) = first_error { return Err(e); }
    Ok(())
}

pub fn list() -> Result<Vec<String>, String> {
    let root = volume_root();
    if !root.exists() { return Ok(Vec::new()); }
    let mut out = Vec::new();
    for item in fs::read_dir(&root).map_err(|e| format!("cannot list volumes: {e}"))? {
        let item = item.map_err(|e| format!("cannot read volume entry: {e}"))?;
        if item.file_type().map_err(|e| format!("cannot inspect volume entry: {e}"))?.is_dir() {
            let name = item.file_name().to_string_lossy().into_owned();
            if valid_name(&name) && item.path().join(".ake-volume").is_file() { out.push(name); }
        }
    }
    out.sort();
    Ok(out)
}

pub fn remove(name: &str) -> Result<(), String> {
    let path = volume_path(name)?;
    if !path.exists() { return Err(format!("volume {name} does not exist")); }
    if !path.is_dir() || !path.join(".ake-volume").is_file() { return Err("refusing to remove a non-AKE volume directory".to_string()); }
    fs::remove_dir_all(&path).map_err(|e| format!("cannot remove volume: {e}"))
}

pub fn env_entries(specs: &[VolumeSpec], run_dir: &Path) -> Vec<(String, String)> {
    specs.iter().flat_map(|spec| {
        let key: String = spec.name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
        let value = target_path(run_dir, &spec.target).to_string_lossy().into_owned();
        let mode = if spec.read_only { "ro" } else { "rw" };
        vec![(format!("AKE_VOLUME_{key}"), value), (format!("AKE_VOLUME_{key}_MODE"), mode.to_string())]
    }).collect()
}
