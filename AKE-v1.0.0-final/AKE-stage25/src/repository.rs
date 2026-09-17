use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{metadata_field, parse_dependencies, version_satisfies, compare_versions};

unsafe extern "C" {
    fn ake_http_download(url: *const i8, destination: *const i8, error: *mut i8, error_size: usize) -> i32;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    pub id: String,
    pub version: String,
    pub architecture: String,
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub repository: String,
}

fn repo_root() -> PathBuf {
    crate::package_db::root().join("repositories")
}

fn repos_file() -> PathBuf {
    repo_root().join("repositories.db")
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.bytes().any(|b| b == b'\0' || b == b'\r' || b == b'\n' || b == b'\t' || b == b'|')
}

pub fn add(name: &str, url: &str) -> Result<(), String> {
    if !valid_token(name, 64) {
        return Err("invalid repository name".to_string());
    }
    if !valid_token(url, 4096) || !(url.starts_with("https://") || url.starts_with("http://") || url.starts_with("file://")) {
        return Err("repository URL must use https://, http://, or file://".to_string());
    }
    let mut repos = list()?;
    if let Some(existing) = repos.iter_mut().find(|r| r.name == name) {
        existing.url = url.to_string();
    } else {
        repos.push(Repository { name: name.to_string(), url: url.to_string() });
    }
    repos.sort_by(|a, b| a.name.cmp(&b.name));
    save(&repos)
}

pub fn remove(name: &str) -> Result<(), String> {
    let mut repos = list()?;
    let before = repos.len();
    repos.retain(|r| r.name != name);
    if repos.len() == before {
        return Err(format!("repository not found: {name}"));
    }
    save(&repos)
}

pub fn list() -> Result<Vec<Repository>, String> {
    let path = repos_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("cannot read repository database: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() { continue; }
        if n == 0 && line == "AKE-REPOS 1" { continue; }
        let mut parts = line.splitn(2, '|');
        let name = parts.next().ok_or_else(|| "malformed repository record".to_string())?;
        let url = parts.next().ok_or_else(|| "malformed repository record".to_string())?;
        if !valid_token(name, 64) || !valid_token(url, 4096) {
            return Err("malformed repository record".to_string());
        }
        out.push(Repository { name: name.to_string(), url: url.to_string() });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn save(repos: &[Repository]) -> Result<(), String> {
    let root = repo_root();
    fs::create_dir_all(&root).map_err(|e| format!("cannot create repository database: {e}"))?;
    let path = repos_file();
    let temp = root.join(format!("repositories.new.{}.{}", std::process::id(), crate::timestamp_seed()));
    let mut text = String::from("AKE-REPOS 1\n");
    for repo in repos {
        text.push_str(&repo.name);
        text.push('|');
        text.push_str(&repo.url);
        text.push('\n');
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)
        .map_err(|e| format!("cannot create repository transaction: {e}"))?;
    file.write_all(text.as_bytes()).map_err(|e| format!("cannot write repository database: {e}"))?;
    file.sync_all().map_err(|e| format!("cannot flush repository database: {e}"))?;
    drop(file);
    if let Err(e) = fs::rename(&temp, &path) {
        let _ = fs::remove_file(&temp);
        return Err(format!("cannot commit repository database: {e}"));
    }
    Ok(())
}

fn join_url(base: &str, child: &str) -> String {
    if child.contains("://") { return child.to_string(); }
    if base.starts_with("file://") {
        let base_path = Path::new(&base[7..]);
        return format!("file://{}", base_path.join(child).display());
    }
    format!("{}/{}", base.trim_end_matches('/'), child.trim_start_matches('/'))
}

fn read_source(url: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return fs::read(path).map_err(|e| format!("cannot read repository file {path}: {e}"));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        let temp = std::env::temp_dir().join(format!("ake-repo-{}-{}", std::process::id(), crate::timestamp_seed()));
        let cu = std::ffi::CString::new(url).map_err(|_| "invalid repository URL".to_string())?;
        let cp = std::ffi::CString::new(temp.to_string_lossy().as_bytes()).map_err(|_| "invalid temporary path".to_string())?;
        let mut err = vec![0i8; 1024];
        let rc = unsafe { ake_http_download(cu.as_ptr(), cp.as_ptr(), err.as_mut_ptr(), err.len()) };
        if rc != 0 {
            let msg = unsafe { std::ffi::CStr::from_ptr(err.as_ptr()) }.to_string_lossy().into_owned();
            let _ = fs::remove_file(&temp);
            return Err(if msg.is_empty() { format!("repository download failed (code {rc})") } else { msg });
        }
        let bytes = fs::read(&temp).map_err(|e| format!("cannot read downloaded repository data: {e}"));
        let _ = fs::remove_file(&temp);
        return bytes;
    }
    Err("unsupported repository URL".to_string())
}

pub fn refresh(repo: &Repository) -> Result<Vec<PackageRecord>, String> {
    let index_url = join_url(&repo.url, "index.ake-repo");
    let bytes = read_source(&index_url)?;
    let text = String::from_utf8(bytes).map_err(|_| "repository index is not UTF-8".to_string())?;
    parse_index(repo, &text)
}

fn parse_index(repo: &Repository, text: &str) -> Result<Vec<PackageRecord>, String> {
    let mut out = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') { continue; }
        if line_no == 0 && line == "AKE-REPO 1" { continue; }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 6 {
            return Err(format!("malformed repository index line {}", line_no + 1));
        }
        let rec = PackageRecord {
            id: fields[0].to_string(),
            version: fields[1].to_string(),
            architecture: fields[2].to_string(),
            name: fields[3].to_string(),
            url: join_url(&repo.url, fields[4]),
            sha256: fields[5].to_ascii_lowercase(),
            repository: repo.name.clone(),
        };
        if !crate::dependency_id_valid(&rec.id) || rec.version.is_empty() || rec.architecture.is_empty() || rec.name.is_empty()
            || rec.sha256.len() != 64 || rec.sha256.bytes().any(|b| !b.is_ascii_hexdigit()) {
            return Err(format!("invalid package record on line {}", line_no + 1));
        }
        out.push(rec);
    }
    Ok(out)
}

pub fn search(term: &str) -> Result<Vec<PackageRecord>, String> {
    let mut all = Vec::new();
    for repo in list()? {
        let entries = refresh(&repo)?;
        all.extend(entries.into_iter().filter(|p| {
            let needle = term.to_ascii_lowercase();
            p.id.to_ascii_lowercase().contains(&needle) || p.name.to_ascii_lowercase().contains(&needle)
        }));
    }
    all.sort_by(|a, b| b.version.cmp(&a.version).then_with(|| a.id.cmp(&b.id)).then_with(|| a.repository.cmp(&b.repository)));
    Ok(all)
}

pub fn find_best(id: &str, constraint: &str, architecture: &str) -> Result<PackageRecord, String> {
    let mut candidates = Vec::new();
    for repo in list()? {
        for p in refresh(&repo)? {
            if p.id == id && (p.architecture == architecture || p.architecture == "any") && version_satisfies(&p.version, constraint) {
                candidates.push(p);
            }
        }
    }
    candidates.into_iter().max_by(|a, b| {
        compare_versions(&a.version, &b.version)
            .then_with(|| b.repository.cmp(&a.repository))
    }).ok_or_else(|| format!("package not found in repositories: {id}{constraint}"))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }
    let mut h = [0x6a09e667u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(((data.len()+9+63)/64)*64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() + 8) % 64 != 0 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes([chunk[i*4],chunk[i*4+1],chunk[i*4+2],chunk[i*4+3]]); }
        for i in 16..64 {
            let s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            let s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh) = (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(temp1); d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b); h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f); h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for b in digest { out.push_str(&format!("{b:02x}")); }
    out
}

pub fn download_package(record: &PackageRecord) -> Result<PathBuf, String> {
    let temp = std::env::temp_dir().join(format!("ake-package-{}-{}.ake", std::process::id(), crate::timestamp_seed()));
    if record.url.starts_with("file://") {
        fs::copy(&record.url[7..], &temp).map_err(|e| format!("cannot copy package from repository: {e}"))?;
    } else if record.url.starts_with("http://") || record.url.starts_with("https://") {
        let cu = std::ffi::CString::new(record.url.as_bytes()).map_err(|_| "invalid package URL".to_string())?;
        let cp = std::ffi::CString::new(temp.to_string_lossy().as_bytes()).map_err(|_| "invalid temporary path".to_string())?;
        let mut err = vec![0i8; 1024];
        let rc = unsafe { ake_http_download(cu.as_ptr(), cp.as_ptr(), err.as_mut_ptr(), err.len()) };
        if rc != 0 {
            let msg = unsafe { std::ffi::CStr::from_ptr(err.as_ptr()) }.to_string_lossy().into_owned();
            let _ = fs::remove_file(&temp);
            return Err(if msg.is_empty() { format!("package download failed (code {rc})") } else { msg });
        }
    } else {
        return Err("unsupported package URL".to_string());
    }
    let bytes = fs::read(&temp).map_err(|e| format!("cannot read downloaded package: {e}"))?;
    let actual = hex_sha256(&bytes);
    if actual != record.sha256 {
        let _ = fs::remove_file(&temp);
        return Err(format!("SHA-256 mismatch for {}: expected {}, got {}", record.id, record.sha256, actual));
    }
    Ok(temp)
}


pub fn signature_path_for(package: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", package.display()))
}

pub fn download_signature(record: &PackageRecord, package: &Path) -> Result<bool, String> {
    let url = format!("{}.sig", record.url);
    let destination = signature_path_for(package);
    if url.starts_with("file://") {
        let source = &url[7..];
        match fs::read(source) {
            Ok(bytes) => {
                if bytes.len() > 1024 * 1024 { return Err("repository signature is too large".to_string()); }
                fs::write(&destination, &bytes).map_err(|e| format!("cannot store repository signature: {e}"))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("cannot read repository signature {source}: {e}")),
        }
    } else if url.starts_with("http://") || url.starts_with("https://") {
        let cu = std::ffi::CString::new(url.as_bytes()).map_err(|_| "invalid signature URL".to_string())?;
        let cp = std::ffi::CString::new(destination.to_string_lossy().as_bytes()).map_err(|_| "invalid signature destination".to_string())?;
        let mut err = vec![0i8; 1024];
        let rc = unsafe { ake_http_download(cu.as_ptr(), cp.as_ptr(), err.as_mut_ptr(), err.len()) };
        if rc == 70 { let _ = fs::remove_file(&destination); return Ok(false); }
        if rc != 0 {
            let msg = unsafe { std::ffi::CStr::from_ptr(err.as_ptr()) }.to_string_lossy().into_owned();
            let _ = fs::remove_file(&destination);
            return Err(if msg.is_empty() { format!("signature download failed (code {rc})") } else { msg });
        }
        let size = fs::metadata(&destination).map_err(|e| format!("cannot inspect downloaded signature: {e}"))?.len();
        if size > 1024 * 1024 { let _ = fs::remove_file(&destination); return Err("repository signature is too large".to_string()); }
        Ok(true)
    } else {
        Err("unsupported repository signature URL".to_string())
    }
}

pub fn print_search(entries: &[PackageRecord]) {
    if entries.is_empty() {
        println!("No matching packages.");
        return;
    }
    println!("{:<28} {:<14} {:<10} {:<16} REPOSITORY", "ID", "VERSION", "ARCH", "NAME");
    for p in entries {
        println!("{:<28} {:<14} {:<10} {:<16} {}", p.id, p.version, p.architecture, p.name, p.repository);
    }
}
