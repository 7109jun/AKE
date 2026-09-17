#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemMode {
    Package,
    AppContainer,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMode {
    Children,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    Current,
    Restricted,
    AppContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Host,
    Deny,
    Internet,
    InternetServer,
    PrivateNetwork,
    InternetAndPrivate,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Job-wide committed memory limit in bytes. 0 means unlimited.
    pub memory_bytes: u64,
    /// Hard CPU cap as percentage * 100 (e.g. 50% -> 5000). 0 means unlimited.
    pub cpu_rate_percent_x100: u32,
    /// Maximum number of simultaneously active processes. 0 means unlimited.
    pub active_processes: u32,
    /// Per-process user-mode CPU time limit in 100ns units. 0 means unlimited.
    pub process_user_time_100ns: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { memory_bytes: 0, cpu_rate_percent_x100: 0, active_processes: 0, process_user_time_100ns: 0 }
    }
}

fn parse_scaled_u64(value: &str, units: &[(&str, u64)], what: &str) -> Result<u64, String> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err(format!("empty {what}"));
    }
    let lower = raw.to_ascii_lowercase();
    let (number, multiplier) = units.iter()
        .find_map(|(suffix, factor)| lower.strip_suffix(suffix).map(|v| (v.trim(), *factor)))
        .unwrap_or((lower.as_str(), 1));
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid {what}: {value}"));
    }
    let n: u64 = number.parse().map_err(|_| format!("invalid {what}: {value}"))?;
    n.checked_mul(multiplier).ok_or_else(|| format!("{what} is too large: {value}"))
}

fn parse_memory(value: &str) -> Result<u64, String> {
    parse_scaled_u64(value, &[("gib", 1024 * 1024 * 1024), ("gb", 1000 * 1000 * 1000),
                              ("mib", 1024 * 1024), ("mb", 1000 * 1000),
                              ("kib", 1024), ("kb", 1000), ("b", 1)], "resource.memory")
        .and_then(|v| if v == 0 { Err("resource.memory must be greater than zero".to_string()) } else { Ok(v) })
}

fn parse_cpu(value: &str) -> Result<u32, String> {
    let raw = value.trim().strip_suffix('%').unwrap_or(value.trim());
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid resource.cpu: {value}"));
    }
    let percent: u32 = raw.parse().map_err(|_| format!("invalid resource.cpu: {value}"))?;
    if percent == 0 || percent > 100 {
        return Err("resource.cpu must be between 1 and 100 percent".to_string());
    }
    percent.checked_mul(100).ok_or_else(|| "resource.cpu is too large".to_string())
}

fn parse_processes(value: &str) -> Result<u32, String> {
    let raw = value.trim();
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid resource.processes: {value}"));
    }
    let n: u32 = raw.parse().map_err(|_| format!("invalid resource.processes: {value}"))?;
    if !(1..=4096).contains(&n) {
        return Err("resource.processes must be between 1 and 4096".to_string());
    }
    Ok(n)
}

fn parse_cpu_time(value: &str) -> Result<u64, String> {
    let ticks = parse_scaled_u64(value, &[("ms", 10_000), ("s", 10_000_000), ("m", 600_000_000), ("h", 36_000_000_000)], "resource.cpu-time")?;
    if ticks == 0 {
        return Err("resource.cpu-time must be greater than zero".to_string());
    }
    Ok(ticks)
}

pub fn parse_resources(info: &str) -> Result<ResourceLimits, String> {
    let mut limits = ResourceLimits::default();
    if let Some(v) = value(info, "resource.memory") {
        limits.memory_bytes = parse_memory(v)?;
    }
    if let Some(v) = value(info, "resource.cpu") {
        limits.cpu_rate_percent_x100 = parse_cpu(v)?;
    }
    if let Some(v) = value(info, "resource.processes") {
        limits.active_processes = parse_processes(v)?;
    }
    if let Some(v) = value(info, "resource.cpu-time") {
        limits.process_user_time_100ns = parse_cpu_time(v)?;
    }
    let any = limits.memory_bytes != 0 || limits.cpu_rate_percent_x100 != 0 ||
              limits.active_processes != 0 || limits.process_user_time_100ns != 0;
    if any {
        if let Some(process) = value(info, "permission.process") {
            if process.trim() == "host" {
                return Err("resource limits require permission.process=children".to_string());
            }
        }
    }
    Ok(limits)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub filesystem: FilesystemMode,
    pub process: ProcessMode,
    pub network: NetworkMode,
    pub identity: IdentityMode,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            filesystem: FilesystemMode::Package,
            process: ProcessMode::Children,
            network: NetworkMode::Host,
            identity: IdentityMode::Current,
        }
    }
}

fn value<'a>(info: &'a str, key: &str) -> Option<&'a str> {
    info.lines().find_map(|line| line.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
}

pub fn parse_policy(info: &str) -> Result<Policy, String> {
    let mut policy = Policy::default();
    let mut network_explicit = false;
    if let Some(v) = value(info, "permission.filesystem") {
        policy.filesystem = match v.trim() {
            "package" => FilesystemMode::Package,
            "appcontainer" => FilesystemMode::AppContainer,
            "host" => FilesystemMode::Host,
            other => return Err(format!("invalid permission.filesystem value: {other}")),
        };
    }
    if let Some(v) = value(info, "permission.process") {
        policy.process = match v.trim() {
            "children" => ProcessMode::Children,
            "host" => ProcessMode::Host,
            other => return Err(format!("invalid permission.process value: {other}")),
        };
    }
    if let Some(v) = value(info, "permission.network") {
        network_explicit = true;
        policy.network = match v.trim() {
            "host" => NetworkMode::Host,
            "deny" | "none" => NetworkMode::Deny,
            "internet" => NetworkMode::Internet,
            "internet-server" => NetworkMode::InternetServer,
            "private" | "private-network" => NetworkMode::PrivateNetwork,
            "internet-and-private" | "all" => NetworkMode::InternetAndPrivate,
            other => return Err(format!("invalid permission.network value: {other}")),
        };
    }
    if let Some(v) = value(info, "permission.identity") {
        policy.identity = match v.trim() {
            "current" | "host" => IdentityMode::Current,
            "restricted" | "least" => IdentityMode::Restricted,
            "appcontainer" => IdentityMode::AppContainer,
            other => return Err(format!("invalid permission.identity value: {other}")),
        };
    } else if policy.filesystem == FilesystemMode::AppContainer {
        policy.identity = IdentityMode::AppContainer;
    }
    if policy.identity == IdentityMode::AppContainer && policy.filesystem != FilesystemMode::AppContainer {
        return Err("permission.identity=appcontainer requires permission.filesystem=appcontainer".to_string());
    }
    if policy.filesystem == FilesystemMode::AppContainer && policy.identity != IdentityMode::AppContainer {
        return Err("permission.filesystem=appcontainer requires permission.identity=appcontainer".to_string());
    }
    if policy.identity == IdentityMode::Restricted && policy.filesystem == FilesystemMode::AppContainer {
        return Err("permission.identity=restricted is incompatible with permission.filesystem=appcontainer".to_string());
    }
    match policy.network {
        NetworkMode::Host => {
            if network_explicit && policy.filesystem == FilesystemMode::AppContainer {
                return Err("permission.network=host is incompatible with AppContainer; use deny, internet, internet-server, private-network, or internet-and-private".to_string());
            }
        }
        _ if policy.filesystem != FilesystemMode::AppContainer => {
            return Err("network isolation requires permission.filesystem=appcontainer".to_string());
        }
        _ => {}
    }
    Ok(policy)
}
