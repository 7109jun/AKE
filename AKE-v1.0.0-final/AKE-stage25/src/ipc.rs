#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl PortProtocol {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(format!("invalid port protocol: {other}")),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self { Self::Tcp => "tcp", Self::Udp => "udp" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishMode {
    None,
    Loopback,
    Lan,
}

impl PublishMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "internal" => Ok(Self::None),
            "loopback" => Ok(Self::Loopback),
            "lan" => Ok(Self::Lan),
            other => Err(format!("invalid port publish mode: {other}")),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self { Self::None => "none", Self::Loopback => "loopback", Self::Lan => "lan" }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub name: String,
    pub protocol: PortProtocol,
    pub container: u16,
    pub host: Option<u16>,
    pub publish: PublishMode,
}

fn key_parts(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("port.")?;
    let (name, field) = rest.split_once('.')?;
    let (key, value) = field.split_once('=')?;
    Some((name, key, value))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && name.bytes().all(|b|
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn parse_port(value: &str, field: &str) -> Result<u16, String> {
    let n: u16 = value.trim().parse().map_err(|_| format!("invalid {field}: {value}"))?;
    if n == 0 { return Err(format!("{field} must be between 1 and 65535")); }
    Ok(n)
}

pub fn parse_specs(info: &str) -> Result<Vec<PortSpec>, String> {
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Partial { protocol: Option<PortProtocol>, container: Option<u16>, host: Option<u16>, publish: Option<PublishMode> }
    let mut map = BTreeMap::<String, Partial>::new();
    for line in info.lines() {
        let Some((name, field, value)) = key_parts(line) else { continue };
        if !valid_name(name) { return Err(format!("invalid port name: {name}")); }
        let p = map.entry(name.to_string()).or_default();
        match field {
            "protocol" => p.protocol = Some(PortProtocol::parse(value)?),
            "container" => p.container = Some(parse_port(value, "port container")?),
            "host" => p.host = Some(parse_port(value, "port host")?),
            "publish" => p.publish = Some(PublishMode::parse(value)?),
            other => return Err(format!("unknown port field for {name}: {other}")),
        }
    }
    let mut out = Vec::new();
    for (name, p) in map {
        let container = p.container.ok_or_else(|| format!("port.{name}.container is required"))?;
        let protocol = p.protocol.unwrap_or(PortProtocol::Tcp);
        let host = p.host;
        let publish = p.publish.unwrap_or(PublishMode::None);
        match publish {
            PublishMode::None => {},
            PublishMode::Loopback | PublishMode::Lan => {
                if host.is_none() { return Err(format!("port.{name}.host is required when publishing")); }
            }
        }
        out.push(PortSpec { name, protocol, container, host, publish });
    }
    for i in 0..out.len() {
        for j in (i + 1)..out.len() {
            if out[i].protocol == out[j].protocol && out[i].host == out[j].host && out[i].host.is_some() {
                return Err(format!("duplicate published {} port", out[i].host.unwrap()));
            }
        }
    }
    Ok(out)
}

fn safe_env_name(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect()
}

pub fn env_entries(specs: &[PortSpec]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in specs {
        let n = safe_env_name(&p.name);
        out.push((format!("AKE_PORT_{n}_PROTOCOL"), p.protocol.as_str().to_string()));
        out.push((format!("AKE_PORT_{n}_CONTAINER"), p.container.to_string()));
        out.push((format!("AKE_PORT_{n}_PUBLISH"), p.publish.as_str().to_string()));
        if let Some(host) = p.host { out.push((format!("AKE_PORT_{n}_HOST"), host.to_string())); }
    }
    out
}

pub fn format_table(specs: &[PortSpec]) -> String {
    let mut out = String::new();
    out.push_str("NAME\tPROTO\tCONTAINER\tHOST\tPUBLISH\n");
    for p in specs {
        out.push_str(&format!("{}\t{}\t{}\t{}\t{}\n", p.name, p.protocol.as_str(), p.container,
                              p.host.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()), p.publish.as_str()));
    }
    out
}
