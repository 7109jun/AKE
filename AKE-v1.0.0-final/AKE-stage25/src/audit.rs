use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FORMAT_VERSION: &str = "AKE-AUDIT 1";

#[derive(Debug, Clone, Copy)]
pub struct EventDef {
    pub id: &'static str,
    pub name: &'static str,
}

pub const PACKAGE_VERIFY: EventDef = EventDef { id: "AKE-AUDIT-001", name: "package.verify" };
pub const PACKAGE_PACK: EventDef = EventDef { id: "AKE-AUDIT-002", name: "package.pack" };
pub const PACKAGE_EXTRACT: EventDef = EventDef { id: "AKE-AUDIT-003", name: "package.extract" };
pub const INSTALL_BEGIN: EventDef = EventDef { id: "AKE-AUDIT-010", name: "package.install.begin" };
pub const INSTALL_OK: EventDef = EventDef { id: "AKE-AUDIT-011", name: "package.install.ok" };
pub const INSTALL_FAIL: EventDef = EventDef { id: "AKE-AUDIT-012", name: "package.install.fail" };
pub const UPDATE_BEGIN: EventDef = EventDef { id: "AKE-AUDIT-020", name: "package.update.begin" };
pub const UPDATE_OK: EventDef = EventDef { id: "AKE-AUDIT-021", name: "package.update.ok" };
pub const UPDATE_FAIL: EventDef = EventDef { id: "AKE-AUDIT-022", name: "package.update.fail" };
pub const REMOVE_OK: EventDef = EventDef { id: "AKE-AUDIT-030", name: "package.remove.ok" };
pub const REMOVE_FAIL: EventDef = EventDef { id: "AKE-AUDIT-031", name: "package.remove.fail" };
pub const RUN_START: EventDef = EventDef { id: "AKE-AUDIT-040", name: "container.run.start" };
pub const RUN_EXIT: EventDef = EventDef { id: "AKE-AUDIT-041", name: "container.run.exit" };
pub const RUN_STOP: EventDef = EventDef { id: "AKE-AUDIT-042", name: "container.run.stop" };
pub const TRUST_ACCEPTED: EventDef = EventDef { id: "AKE-AUDIT-050", name: "trust.accepted" };
pub const TRUST_REJECTED: EventDef = EventDef { id: "AKE-AUDIT-051", name: "trust.rejected" };
pub const POLICY_DENIED: EventDef = EventDef { id: "AKE-AUDIT-060", name: "policy.denied" };
pub const SERVICE_ACTION: EventDef = EventDef { id: "AKE-AUDIT-070", name: "service.action" };
pub const CLI_COMMAND: EventDef = EventDef { id: "AKE-AUDIT-080", name: "cli.command" };

fn root() -> PathBuf {
    std::env::var_os("AKE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(windows) { PathBuf::from(r"C:\ProgramData\AKE") } else { PathBuf::from("ake-data") }
        })
}

fn audit_dir() -> PathBuf { root().join("audit") }
fn audit_path() -> PathBuf { audit_dir().join("audit.log") }

fn unix_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '=' => out.push_str("\\="),
            '|' => out.push_str("\\p"),
            _ => out.push(ch),
        }
    }
    out
}

fn unescape(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            out.push(match ch {
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '=' => '=',
                'p' => '|',
                other => return Err(format!("invalid audit escape \\{other}")),
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped { return Err("trailing escape in audit record".to_string()); }
    Ok(out)
}

fn split_fields(line: &str) -> Result<Vec<(&str, &str)>, String> {
    let bytes = line.as_bytes();
    let mut fields = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= bytes.len() {
        if i == bytes.len() || bytes[i] == b'|' {
            let segment = &line[start..i];
            let mut eq = None;
            let mut j = 0usize;
            let seg_bytes = segment.as_bytes();
            while j < seg_bytes.len() {
                if seg_bytes[j] == b'\\' { j += 2; continue; }
                if seg_bytes[j] == b'=' { eq = Some(j); break; }
                j += 1;
            }
            let pos = eq.ok_or_else(|| "malformed audit record".to_string())?;
            fields.push((&segment[..pos], &segment[pos + 1..]));
            start = i + 1;
        }
        if i == bytes.len() { break; }
        if bytes[i] == b'\\' { i += 2; } else { i += 1; }
    }
    Ok(fields)
}

#[derive(Debug, Clone)]
pub struct Event {
    pub timestamp_ms: u128,
    pub event: String,
    pub name: String,
    pub result: String,
    pub pid: u32,
    pub package_id: String,
    pub version: String,
    pub details: String,
}

pub fn log(def: EventDef, result: &'static str, package_id: &str, version: &str, details: &str) -> Result<(), String> {
    fs::create_dir_all(audit_dir()).map_err(|e| format!("cannot create audit directory: {e}"))?;
    let line = format!(
        "version={FORMAT_VERSION}|timestamp_ms={}|event={}|name={}|result={}|pid={}|package_id={}|package_version={}|details={}\n",
        unix_millis(), def.id, def.name, result, std::process::id(),
        escape(package_id), escape(version), escape(details)
    );
    let path = audit_path();
    let mut file = OpenOptions::new().create(true).append(true).open(&path)
        .map_err(|e| format!("cannot open audit log: {e}"))?;
    file.write_all(line.as_bytes()).map_err(|e| format!("cannot append audit event: {e}"))?;
    file.sync_data().map_err(|e| format!("cannot flush audit event: {e}"))?;
    Ok(())
}

pub fn list(limit: Option<usize>) -> Result<Vec<String>, String> {
    if !audit_path().is_file() { return Ok(Vec::new()); }
    let file = File::open(audit_path()).map_err(|e| format!("cannot open audit log: {e}"))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("cannot read audit log: {e}"))?;
        if !line.trim().is_empty() { lines.push(line); }
    }
    if let Some(n) = limit {
        let start = lines.len().saturating_sub(n);
        return Ok(lines.split_off(start));
    }
    Ok(lines)
}

pub fn parse_line(line: &str) -> Result<Event, String> {
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in split_fields(line.trim_end_matches(&['\n', '\r'][..]))? {
        fields.insert(unescape(key)?, unescape(value)?);
    }
    if fields.get("version").map(String::as_str) != Some(FORMAT_VERSION) {
        return Err("unsupported audit record version".to_string());
    }
    let timestamp_ms = fields.get("timestamp_ms").ok_or("audit timestamp missing")?.parse::<u128>().map_err(|_| "invalid audit timestamp".to_string())?;
    let pid = fields.get("pid").ok_or("audit pid missing")?.parse::<u32>().map_err(|_| "invalid audit pid".to_string())?;
    Ok(Event {
        timestamp_ms,
        event: fields.get("event").cloned().unwrap_or_default(),
        name: fields.get("name").cloned().unwrap_or_default(),
        result: fields.get("result").cloned().unwrap_or_default(),
        pid,
        package_id: fields.get("package_id").cloned().unwrap_or_default(),
        version: fields.get("package_version").cloned().unwrap_or_default(),
        details: fields.get("details").cloned().unwrap_or_default(),
    })
}

pub fn show(limit: Option<usize>) -> Result<Vec<Event>, String> {
    let raw = list(limit)?;
    raw.into_iter().map(|line| parse_line(&line)).collect()
}

pub fn clear() -> Result<(), String> {
    let path = audit_path();
    if path.exists() { fs::remove_file(&path).map_err(|e| format!("cannot clear audit log: {e}"))?; }
    Ok(())
}

pub fn path() -> PathBuf { audit_path() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_escape_roundtrip() {
        let value = "a|b=c\n\r\t\\";
        assert_eq!(unescape(&escape(value)).unwrap(), value);
    }

    #[test]
    fn audit_line_roundtrip() {
        let line = "version=AKE-AUDIT 1|timestamp_ms=123|event=AKE-AUDIT-080|name=cli.command|result=ok|pid=7|package_id=a\\=b|package_version=1.0.0|details=x\\p y";
        let event = parse_line(line).unwrap();
        assert_eq!(event.event, CLI_COMMAND.id);
        assert_eq!(event.name, CLI_COMMAND.name);
        assert_eq!(event.result, "ok");
        assert_eq!(event.package_id, "a=b");
        assert_eq!(event.details, "x| y");
    }
}
