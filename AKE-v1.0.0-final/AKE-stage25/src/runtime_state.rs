use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Running,
    Stopping,
    Exited,
    Stopped,
    Failed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Exited => "exited",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "running" => Self::Running,
            "stopping" => Self::Stopping,
            "exited" => Self::Exited,
            "stopped" => Self::Stopped,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub id: String,
    pub package_id: String,
    pub version: String,
    pub architecture: String,
    pub pid: u32,
    pub started_unix: u64,
    pub status: Status,
    pub exit_code: Option<i32>,
    pub package_root: PathBuf,
    pub entry: String,
    pub log_path: PathBuf,
    pub job_name: String,
    pub cleanup_runtime: bool,
}

fn root() -> PathBuf {
    std::env::var_os("AKE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(windows) {
                PathBuf::from(r"C:\ProgramData\AKE")
            } else {
                PathBuf::from("ake-data")
            }
        })
}

fn state_dir() -> PathBuf { root().join("runtime").join("state") }
fn log_dir() -> PathBuf { root().join("runtime").join("logs") }
fn state_path(id: &str) -> PathBuf { state_dir().join(format!("{id}.state")) }

pub fn prepare() -> Result<(), String> {
    fs::create_dir_all(state_dir()).map_err(|e| format!("cannot create runtime state directory: {e}"))?;
    fs::create_dir_all(log_dir()).map_err(|e| format!("cannot create runtime log directory: {e}"))?;
    Ok(())
}

pub fn new_id() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("run-{:x}-{:x}", now.as_nanos(), std::process::id())
}

pub fn default_log_path(id: &str) -> PathBuf { log_dir().join(format!("{id}.log")) }

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '=' => out.push_str("\\="),
            _ => out.push(ch),
        }
    }
    out
}

fn decode(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            out.push(match ch {
                'n' => '\n',
                'r' => '\r',
                '\\' => '\\',
                '=' => '=',
                other => return Err(format!("invalid escape sequence: \\{other}")),
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped { return Err("trailing escape in state record".to_string()); }
    Ok(out)
}

pub fn write(record: &RunRecord) -> Result<(), String> {
    prepare()?;
    let path = state_path(&record.id);
    let tmp = state_dir().join(format!("{}.state.tmp-{}", record.id, std::process::id()));
    let body = format!(
        "id={}\npackage_id={}\nversion={}\narchitecture={}\npid={}\nstarted_unix={}\nstatus={}\nexit_code={}\npackage_root={}\nentry={}\nlog_path={}\njob_name={}\ncleanup_runtime={}\n",
        encode(&record.id), encode(&record.package_id), encode(&record.version), encode(&record.architecture),
        record.pid, record.started_unix, record.status.as_str(),
        record.exit_code.map(|v| v.to_string()).unwrap_or_else(|| "".to_string()),
        encode(&record.package_root.to_string_lossy()), encode(&record.entry),
        encode(&record.log_path.to_string_lossy()), encode(&record.job_name), record.cleanup_runtime,
    );
    {
        let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)
            .map_err(|e| format!("cannot write runtime state: {e}"))?;
        file.write_all(body.as_bytes()).map_err(|e| format!("cannot write runtime state: {e}"))?;
        file.sync_all().map_err(|e| format!("cannot flush runtime state: {e}"))?;
    }
    #[cfg(windows)]
    {
        if path.exists() { fs::remove_file(&path).map_err(|e| format!("cannot replace runtime state: {e}"))?; }
    }
    fs::rename(&tmp, &path).map_err(|e| format!("cannot commit runtime state: {e}"))?;
    Ok(())
}

pub fn read(path: &Path) -> Result<RunRecord, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read runtime state: {e}"))?;
    let mut values = std::collections::HashMap::<String, String>::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        values.insert(key.to_string(), decode(value)?);
    }
    let get = |key: &str| values.get(key).cloned().ok_or_else(|| format!("runtime state missing {key}"));
    let id = get("id")?;
    let status = Status::parse(&get("status")?).ok_or_else(|| "invalid runtime state status".to_string())?;
    let exit_code = match get("exit_code")?.as_str() { "" => None, value => Some(value.parse::<i32>().map_err(|_| "invalid runtime exit code".to_string())?) };
    Ok(RunRecord {
        id,
        package_id: get("package_id")?,
        version: get("version")?,
        architecture: get("architecture")?,
        pid: get("pid")?.parse::<u32>().map_err(|_| "invalid runtime pid".to_string())?,
        started_unix: get("started_unix")?.parse::<u64>().map_err(|_| "invalid runtime start time".to_string())?,
        status,
        exit_code,
        package_root: PathBuf::from(get("package_root")?),
        entry: get("entry")?,
        log_path: PathBuf::from(get("log_path")?),
        job_name: get("job_name")?,
        cleanup_runtime: get("cleanup_runtime")? == "true",
    })
}

pub fn list() -> Result<Vec<RunRecord>, String> {
    prepare()?;
    let mut out = Vec::new();
    for item in fs::read_dir(state_dir()).map_err(|e| format!("cannot list runtime state: {e}"))? {
        let item = item.map_err(|e| format!("cannot read runtime state entry: {e}"))?;
        let path = item.path();
        if path.extension().and_then(|x| x.to_str()) != Some("state") { continue; }
        match read(&path) {
            Ok(record) => out.push(record),
            Err(_) => continue,
        }
    }
    out.sort_by(|a, b| b.started_unix.cmp(&a.started_unix).then_with(|| a.id.cmp(&b.id)));
    Ok(out)
}

pub fn find(id: &str) -> Result<RunRecord, String> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        return Err("invalid run id".to_string());
    }
    read(&state_path(id))
}

pub fn update(record: &RunRecord) -> Result<(), String> { write(record) }

pub fn read_logs(record: &RunRecord) -> Result<String, String> {
    let mut file = fs::File::open(&record.log_path).map_err(|e| format!("cannot open log: {e}"))?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|e| format!("cannot read log: {e}"))?;
    Ok(text)
}

pub fn tail_lines(record: &RunRecord, count: usize) -> Result<String, String> {
    if count == 0 { return Ok(String::new()); }
    let text = read_logs(record)?;
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(count);
    Ok(lines[start..].join("\n") + if start < lines.len() { "\n" } else { "" })
}
