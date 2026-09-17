use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod package_db;
mod repository;
mod signing;
mod trust;
mod isolation;
mod runtime_state;
mod volume;
mod ipc;
mod windows_integration;
mod service;
mod audit;
unsafe extern "C" {
    fn ake_validate_package(path: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_package_info(path: *const i8, out: *mut i8, out_size: usize) -> i32;
    fn ake_pack_directory(source: *const i8, output: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_extract_package(package: *const i8, destination: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_spawn_process(program: *const i8, arguments: *const i8) -> i32;
    fn ake_spawn_process_in_directory(program: *const i8, arguments: *const i8, working_directory: *const i8, exit_code: *mut i32) -> i32;
    fn ake_spawn_process_in_directory_with_environment(program: *const i8, arguments: *const i8, working_directory: *const i8, environment_block_utf8: *const u8, environment_size: usize, exit_code: *mut i32) -> i32;
    fn ake_http_download(url: *const i8, destination: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_spawn_isolated_process(program: *const i8, arguments: *const i8, working_directory: *const i8, environment_block_utf8: *const u8, environment_size: usize, container_name: *const i8, filesystem_mode: i32, process_mode: i32, network_mode: i32, identity_mode: i32, memory_limit_bytes: u64, cpu_rate_percent_x100: u32, active_process_limit: u32, process_user_time_100ns: u64, exit_code: *mut i32) -> i32;
    fn ake_spawn_isolated_process_detached(program: *const i8, arguments: *const i8, working_directory: *const i8, environment_block_utf8: *const u8, environment_size: usize, container_name: *const i8, filesystem_mode: i32, process_mode: i32, network_mode: i32, identity_mode: i32, memory_limit_bytes: u64, cpu_rate_percent_x100: u32, active_process_limit: u32, process_user_time_100ns: u64, job_name: *const i8, log_path: *const i8, pid_out: *mut u32) -> i32;
    fn ake_query_process(pid: u32, running: *mut i32, exit_code: *mut i32) -> i32;
    fn ake_terminate_job_or_process(job_name: *const i8, pid: u32) -> i32;
    fn ake_ipc_build_pipe_name(container_name: *const i8, channel: *const i8, out: *mut i8, out_size: usize) -> i32;
    fn ake_ipc_server_once(pipe_name: *const i8, response: *const u8, response_size: usize, timeout_ms: u32) -> i32;
    fn ake_ipc_client_call(pipe_name: *const i8, request: *const u8, request_size: usize, response: *mut u8, response_capacity: usize, response_size: *mut usize, timeout_ms: u32) -> i32;
    fn ake_registry_set_classes(key: *const i8, value_name: *const i8, value_data: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_registry_query_classes(key: *const i8, value_name: *const i8, out: *mut i8, out_size: usize) -> i32;
    fn ake_registry_delete_classes(key: *const i8, value_name: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_registry_delete_tree_classes(key: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_create_shortcut(kind: *const i8, name: *const i8, target: *const i8, arguments: *const i8, working_directory: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_remove_shortcut(kind: *const i8, name: *const i8, error: *mut i8, error_size: usize) -> i32;
}

fn c_string(ptr: *const i8) -> String {
    if ptr.is_null() { return String::new(); }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

fn print_help() {
    println!("AKE v1.0 — Windows Application Package & Container");
    println!("Usage:");
    println!("  ake verify <package.ake>");
    println!("  ake info   <package.ake>");
    println!("  ake run    [--detach] <package.ake|package-id> [args...]");
    println!("  ake pack   <source-dir> <output.ake>");
    println!("  ake extract <package.ake> <destination-dir>");
    println!("  ake install <package.ake>");
    println!("  ake update  <package.ake>");
    println!("  ake remove  <package-id>");
    println!("  ake list");
    println!("  ake which <package-id>");
    println!("  ake ps [--all]");
    println!("  ake logs <run-id> [--tail <lines>]");
    println!("  ake stop <run-id>");
    println!("  ake search <term>");
    println!("  ake repo add <name> <url>");
    println!("  ake repo remove <name>");
    println!("  ake repo list");
    println!("  ake keygen <private.akekey> <public.akepub>");
    println!("  ake sign <package.ake> <private.akekey> [signature.ake.sig]");
    println!("  ake verify-signature <package.ake> [signature.ake.sig]");
    println!("  ake trust add <public.akepub> [name]");
    println!("  ake trust remove <key-id>");
    println!("  ake trust list");
    println!("  ake trust verify <package.ake> [signature.ake.sig]");
    println!("  ake trust policy");
    println!("  ake trust policy set <local|repository> <allow-unsigned|require-trusted>");
    println!("  ake volume create <name>");
    println!("  ake volume list");
    println!("  ake volume remove <name>");
    println!("  ake ports <package.ake|package-id>");
    println!("  ake ipc name <container-name> <channel>");
    println!("  ake ipc serve <container-name> <channel> <response> [timeout-ms]");
    println!("  ake ipc call <pipe-name> <message> [timeout-ms]");
    println!("  ake integration install <package-id>");
    println!("  ake integration remove <package-id>");
    println!("  ake integration status <package-id>");
    println!("  ake service install <package-id>");
    println!("  ake service remove <package-id>");
    println!("  ake service start <package-id>");
    println!("  ake service stop <package-id>");
    println!("  ake service status <package-id>");
    println!("  ake audit list [--limit <n>]");
    println!("  ake audit clear");
    println!("  install accepts either a .ake file or a package ID from configured repositories.");
    println!("  Repository index: <base>/index.ake-repo (tab-separated records). ");
    println!("  AKE_ROOT=<path> overrides the package database root for testing/custom deployment.");
    println!("  Package metadata may contain repeated dependency=<id>[constraint] lines.");
    println!("  Isolation metadata: permission.filesystem=package|appcontainer|host; permission.process=children|host; permission.identity=current|restricted|appcontainer");
    println!("  Network metadata: permission.network=host|deny|internet|internet-server|private-network|internet-and-private");
    println!("  Resource metadata: resource.memory=<bytes|KiB|MiB|GiB>, resource.cpu=<1-100%>, resource.processes=<1-4096>, resource.cpu-time=<ms|s|m|h>");
    println!("  Volume metadata: volume.<name>.source=@<named-volume>|<absolute-host-path>, volume.<name>.target=data/<path>, volume.<name>.mode=rw|ro");
    println!("  Windows integration: registry.<name>.key/value/data, association.<name>.extension/progid/description/command, protocol.<name>.scheme/description/command, shortcut.<name>.name/target/arguments/working-directory/location");
    println!("  Service metadata: service.name/display-name/description/start/account/restart/restart.max-retries/restart.delay/restart.backoff/restart.reset");
    println!("  Service restart: restart=never|on-failure|always; max-retries=0..32; delay=100ms..24h; backoff=1..10; reset=0..365d");
    println!("  Detached containers write stdout/stderr to the AKE runtime log directory.");
    println!("  Audit log: audit/audit.log under AKE_ROOT; events are append-only key/value records.");
}

fn verify(path: &str) -> i32 {
    let cpath = match CString::new(path) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid path"); return 2; }
    };
    let mut error = vec![0i8; 512];
    let rc = unsafe { ake_validate_package(cpath.as_ptr(), error.as_mut_ptr(), error.len()) };
    if rc != 0 {
        let msg = c_string(error.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    let mut info_buf = vec![0i8; 8192];
    let info_rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
    if info_rc != 0 {
        let msg = c_string(info_buf.as_ptr());
        eprintln!("AKE{:03}: {}", info_rc, if msg.is_empty() { "package metadata is invalid" } else { &msg });
        return 1;
    }
    let info_text = c_string(info_buf.as_ptr());
    if let Err(e) = volume::parse_specs(&info_text) {
        eprintln!("AKE018: invalid volume metadata: {e}");
        return 1;
    }
    if let Err(e) = ipc::parse_specs(&info_text) {
        eprintln!("AKE019: invalid port metadata: {e}");
        return 1;
    }
    if let Err(e) = isolation::parse_policy(&info_text) {
        eprintln!("AKE014: invalid isolation policy: {e}");
        return 1;
    }
    if let Err(e) = isolation::parse_resources(&info_text) {
        eprintln!("AKE015: invalid resource policy: {e}");
        return 1;
    }
    if let Some(id) = metadata_field(&info_text, "id") {
        if let Err(e) = service::validate(&info_text, &id) {
            eprintln!("AKE027: invalid service metadata: {e}");
            return 1;
        }
    }
    let (id, version) = audit_pkg(&info_text);
    let _ = audit::log(audit::PACKAGE_VERIFY, "ok", &id, &version, path);
    println!("Valid AKE package: {}", path);
    0
}

fn info(path: &str) -> i32 {
    let cpath = match CString::new(path) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid path"); return 2; }
    };
    let mut output = vec![0i8; 8192];
    let rc = unsafe { ake_package_info(cpath.as_ptr(), output.as_mut_ptr(), output.len()) };
    if rc != 0 {
        let msg = c_string(output.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    print!("{}", c_string(output.as_ptr()));
    0
}


fn pack(source: &str, output: &str) -> i32 {
    let s = match CString::new(source) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid source path"); return 2; }
    };
    let o = match CString::new(output) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid output path"); return 2; }
    };
    let mut error = vec![0i8; 512];
    let rc = unsafe { ake_pack_directory(s.as_ptr(), o.as_ptr(), error.as_mut_ptr(), error.len()) };
    if rc != 0 {
        let msg = c_string(error.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "package creation failed" } else { &msg });
        return 1;
    }
    let _ = audit::log(audit::PACKAGE_PACK, "ok", "", "", output);
    println!("Created AKE package: {}", output);
    0
}

fn extract(path: &str, destination: &str) -> i32 {
    let p = match CString::new(path) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid package path"); return 2; }
    };
    let d = match CString::new(destination) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid destination path"); return 2; }
    };
    let mut error = vec![0i8; 512];
    let rc = unsafe { ake_extract_package(p.as_ptr(), d.as_ptr(), error.as_mut_ptr(), error.len()) };
    if rc != 0 {
        let msg = c_string(error.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "package extraction failed" } else { &msg });
        return 1;
    }
    let _ = audit::log(audit::PACKAGE_EXTRACT, "ok", "", "", &format!("{} -> {}", path, destination));
    println!("Extracted AKE package: {} -> {}", path, destination);
    0
}

fn temp_run_directory(package_path: &Path) -> Result<PathBuf, String> {
    let base = env::temp_dir().join("ake-runtime");
    fs::create_dir_all(&base).map_err(|e| format!("cannot create runtime temp root: {e}"))?;
    let stem = package_path.file_stem().and_then(|s| s.to_str()).unwrap_or("package");
    let safe_stem: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seed = now.as_nanos() ^ ((std::process::id() as u128) << 32);
    for attempt in 0u32..64 {
        let dir = base.join(format!("{safe_stem}-{:032x}-{attempt}", seed));
        if !dir.exists() {
            return Ok(dir);
        }
    }
    Err("cannot allocate a unique runtime directory".to_string())
}

fn package_entry(info: &str) -> Option<&str> {
    info.lines().find_map(|line| line.strip_prefix("entry="))
}

fn metadata_environment(info: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("env.") {
            let (name, value) = rest.split_once('=').ok_or_else(|| format!("invalid environment metadata: {line}"))?;
            if name.is_empty() || name.contains('=') || name.contains('\0') || name.eq_ignore_ascii_case("AKE_PACKAGE_ROOT")
                || name.eq_ignore_ascii_case("AKE_PACKAGE_LIB") || name.eq_ignore_ascii_case("AKE_PACKAGE_CONFIG")
                || name.eq_ignore_ascii_case("AKE_PACKAGE_DATA") {
                return Err(format!("invalid or reserved environment variable name: {name}"));
            }
            if value.contains('\0') {
                return Err(format!("invalid environment variable value for {name}"));
            }
            out.push((name.to_string(), value.to_string()));
        }
    }
    Ok(out)
}

pub(crate) fn build_child_environment(info: &str, run_dir: &Path, mounted_volumes: &[volume::VolumeSpec]) -> Result<Vec<u8>, String> {
    let lib_dir = run_dir.join("lib");
    let config_dir = run_dir.join("config");
    let data_dir = run_dir.join("data");
    fs::create_dir_all(&data_dir).map_err(|e| format!("cannot create data directory: {e}"))?;

    let mut vars: Vec<(String, String)> = env::vars().collect();
    let mut custom = metadata_environment(info)?;

    let root = run_dir.to_string_lossy().into_owned();
    let lib = lib_dir.to_string_lossy().into_owned();
    let config = config_dir.to_string_lossy().into_owned();
    let data = data_dir.to_string_lossy().into_owned();

    let mut path_value = lib.clone();
    if !path_value.is_empty() {
        path_value.push(if cfg!(windows) { ';' } else { ':' });
    }
    if let Ok(host_path) = env::var("PATH") {
        path_value.push_str(&host_path);
    }

    custom.push(("AKE_PACKAGE_ROOT".to_string(), root));
    custom.push(("AKE_PACKAGE_LIB".to_string(), lib));
    custom.push(("AKE_PACKAGE_CONFIG".to_string(), config));
    custom.push(("AKE_PACKAGE_DATA".to_string(), data));
    custom.push(("PATH".to_string(), path_value));
    custom.extend(volume::env_entries(mounted_volumes, run_dir));
    let package_id = metadata_field(info, "id").unwrap_or_else(|| "ake.package".to_string());
    let container_name = container_name_for_package(&package_id);
    let mut pipe_namespace = String::new();
    let mut pipe_buf = vec![0i8; 512];
    if let (Ok(container_c), Ok(channel_c)) = (CString::new(container_name.clone()), CString::new("default")) {
        let rc = unsafe { ake_ipc_build_pipe_name(container_c.as_ptr(), channel_c.as_ptr(), pipe_buf.as_mut_ptr(), pipe_buf.len()) };
        if rc == 0 {
            pipe_namespace = c_string(pipe_buf.as_ptr());
        }
    }
    if let Some(pos) = pipe_namespace.rfind('\\') {
        pipe_namespace.truncate(pos);
    }
    if !pipe_namespace.is_empty() {
        custom.push(("AKE_IPC_NAMESPACE".to_string(), pipe_namespace));
    }
    custom.push(("AKE_CONTAINER_ID".to_string(), package_id));
    if let Ok(port_specs) = ipc::parse_specs(info) {
        custom.extend(ipc::env_entries(&port_specs));
    }

    for (name, value) in custom {
        vars.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
        vars.push((name, value));
    }

    vars.sort_by(|a, b| a.0.to_ascii_uppercase().cmp(&b.0.to_ascii_uppercase()).then_with(|| a.0.cmp(&b.0)));

    let mut block = Vec::<u8>::new();
    for (name, value) in vars {
        if name.contains('=') || name.contains('\0') || value.contains('\0') {
            return Err(format!("invalid environment entry: {name}"));
        }
        let item = format!("{name}={value}");
        block.extend_from_slice(item.as_bytes());
        block.push(0);
    }
    block.push(0);

    Ok(block)
}

fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() { return "\"\"".to_string(); }
    let needs_quotes = arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
    if !needs_quotes { return arg.to_string(); }
    let mut out = String::from("\"");
    let mut slashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
        } else if ch == '"' {
            out.push_str(&"\\".repeat(slashes * 2 + 1));
            out.push('"');
            slashes = 0;
        } else {
            if slashes { out.push_str(&"\\".repeat(slashes)); slashes = 0; }
            out.push(ch);
        }
    }
    if slashes { out.push_str(&"\\".repeat(slashes * 2)); }
    out.push('"');
    out
}

fn safe_entry_path(root: &Path, entry: &str) -> Result<PathBuf, String> {
    if !entry.starts_with("bin/") || !entry.ends_with(".exe") || entry.contains('\\') || entry.contains("..") {
        return Err("package entry is invalid".to_string());
    }
    let rel = entry.strip_prefix("bin/").unwrap_or_default();
    if rel.is_empty() || rel.contains('/') {
        return Err("package entry must name a file directly under bin/".to_string());
    }
    let path = root.join("bin").join(rel);
    if !path.is_file() {
        return Err("package entry executable is missing".to_string());
    }
    Ok(path)
}


fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() { return Err(format!("package source is not a directory: {}", source.display())); }
    fs::create_dir_all(destination).map_err(|e| format!("cannot create runtime directory: {e}"))?;
    for entry in fs::read_dir(source).map_err(|e| format!("cannot read package directory: {e}"))? {
        let entry = entry.map_err(|e| format!("cannot read package entry: {e}"))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| format!("cannot inspect package entry: {e}"))?;
        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).map_err(|e| format!("cannot copy package file {}: {e}", source_path.display()))?;
        } else {
            return Err(format!("unsupported special file in installed package: {}", source_path.display()));
        }
    }
    Ok(())
}

fn prepare_installed_volume_runtime(pkg: &package_db::InstalledPackage, info: &str) -> Result<(PathBuf, Vec<volume::VolumeSpec>), String> {
    let specs = volume::parse_specs(info)?;
    let run_dir = temp_run_directory(Path::new(&pkg.id))?;
    if let Err(e) = copy_dir_recursive(&pkg.install_dir, &run_dir) {
        let _ = fs::remove_dir_all(&run_dir);
        return Err(e);
    }
    let package_data = pkg.install_dir.join("data");
    if !package_data.exists() {
        fs::create_dir_all(&package_data).map_err(|e| {
            let _ = fs::remove_dir_all(&run_dir);
            format!("cannot create persistent package data directory: {e}")
        })?;
    }
    let staged_data = run_dir.join("data");
    if staged_data.exists() {
        let _ = fs::remove_dir_all(&staged_data);
    }
    volume::bind_directory(&package_data, &staged_data, false).map_err(|e| {
        let _ = fs::remove_dir_all(&run_dir);
        e
    })?;
    if let Err(e) = volume::mount_all(&specs, &run_dir) {
        let _ = volume::unmount_directory(&staged_data);
        let _ = fs::remove_dir_all(&run_dir);
        return Err(e);
    }
    Ok((run_dir, specs))
}

fn launch_prepared_package(run_dir: &Path, info: &str, args: &[String], mounted_volumes: &[volume::VolumeSpec]) -> i32 {
    let entry = match package_entry(info) {
        Some(v) => v,
        None => { eprintln!("AKE010: package entry is missing"); return 1; }
    };
    let entry_path = match safe_entry_path(run_dir, entry) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE010: {e}"); return 1; }
    };
    let exe = entry_path.to_string_lossy().into_owned();
    let cwd = run_dir.to_string_lossy().into_owned();
    let argline = args.iter().map(|a| quote_windows_arg(a)).collect::<Vec<_>>().join(" ");
    let exe_c = match CString::new(exe) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid executable path"); return 2; }
    };
    let args_c = match CString::new(argline) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid argument string"); return 2; }
    };
    let cwd_c = match CString::new(cwd) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid working directory"); return 2; }
    };
    let environment = match build_child_environment(info, run_dir, &mounted_volumes) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE014: failed to build package environment: {e}"); return 1; }
    };
    let policy = match isolation::parse_policy(info) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE014: invalid isolation policy: {e}"); return 1; }
    };
    let resources = match isolation::parse_resources(info) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE015: invalid resource policy: {e}"); return 1; }
    };
    let package_id = metadata_field(info, "id").unwrap_or_else(|| "ake.package".to_string());
    let safe_name: String = package_id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }).collect();
    // Windows AppContainer names are limited to 64 characters. Keep the name deterministic
    // while avoiding collisions caused by truncation.
    let mut hash = 0xcbf29ce484222325u64;
    for b in package_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let prefix: String = safe_name.chars().take(39).collect();
    let container_name = format!("AKE_{}-{:016x}", prefix, hash);
    let name_c = match CString::new(container_name) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid container name"); return 2; }
    };
    let filesystem_mode = match policy.filesystem {
        isolation::FilesystemMode::Package => 0,
        isolation::FilesystemMode::AppContainer => 1,
        isolation::FilesystemMode::Host => 2,
    };
    let process_mode = match policy.process {
        isolation::ProcessMode::Children => 0,
        isolation::ProcessMode::Host => 1,
    };
    let network_mode = match policy.network {
        isolation::NetworkMode::Host => 0,
        isolation::NetworkMode::Deny => 1,
        isolation::NetworkMode::Internet => 2,
        isolation::NetworkMode::InternetServer => 3,
        isolation::NetworkMode::PrivateNetwork => 4,
        isolation::NetworkMode::InternetAndPrivate => 5,
    };
    let identity_mode = match policy.identity {
        isolation::IdentityMode::Current => 0,
        isolation::IdentityMode::Restricted => 1,
        isolation::IdentityMode::AppContainer => 2,
    };
    let mut exit_code = 0i32;
    let launch_rc = unsafe {
        ake_spawn_isolated_process(
            exe_c.as_ptr(), args_c.as_ptr(), cwd_c.as_ptr(),
            environment.as_ptr(), environment.len(), name_c.as_ptr(),
            filesystem_mode, process_mode, network_mode, identity_mode,
            resources.memory_bytes, resources.cpu_rate_percent_x100,
            resources.active_processes, resources.process_user_time_100ns,
            &mut exit_code
        )
    };
    if launch_rc != 0 {
        eprintln!("AKE012: failed to launch package entry (code {})", launch_rc);
        return 1;
    }
    exit_code
}



fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn container_job_name(run_id: &str) -> String {
    format!("Local\\AKE-{}", run_id)
}

fn container_name_for_package(package_id: &str) -> String {
    let safe_name: String = package_id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let mut hash = 0xcbf29ce484222325u64;
    for b in package_id.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let prefix: String = safe_name.chars().take(39).collect();
    format!("AKE_{}-{:016x}", prefix, hash)
}

fn container_pipe_name(container_name: &str, channel: &str) -> Result<String, String> {
    let c = CString::new(container_name).map_err(|_| "invalid container name".to_string())?;
    let ch = CString::new(channel).map_err(|_| "invalid IPC channel".to_string())?;
    let mut out = vec![0i8; 512];
    let rc = unsafe { ake_ipc_build_pipe_name(c.as_ptr(), ch.as_ptr(), out.as_mut_ptr(), out.len()) };
    if rc != 0 { return Err(format!("cannot build IPC endpoint (code {rc})")); }
    Ok(c_string(out.as_ptr()))
}

pub(crate) fn launch_parameters(info: &str) -> Result<(isolation::Policy, isolation::ResourceLimits, String, String, i32, i32, i32, i32), String> {
    let policy = isolation::parse_policy(info)?;
    let resources = isolation::parse_resources(info)?;
    let package_id = metadata_field(info, "id").unwrap_or_else(|| "ake.package".to_string());
    let container_name = container_name_for_package(&package_id);
    let filesystem_mode = match policy.filesystem {
        isolation::FilesystemMode::Package => 0,
        isolation::FilesystemMode::AppContainer => 1,
        isolation::FilesystemMode::Host => 2,
    };
    let process_mode = match policy.process {
        isolation::ProcessMode::Children => 0,
        isolation::ProcessMode::Host => 1,
    };
    let network_mode = match policy.network {
        isolation::NetworkMode::Host => 0,
        isolation::NetworkMode::Deny => 1,
        isolation::NetworkMode::Internet => 2,
        isolation::NetworkMode::InternetServer => 3,
        isolation::NetworkMode::PrivateNetwork => 4,
        isolation::NetworkMode::InternetAndPrivate => 5,
    };
    let identity_mode = match policy.identity {
        isolation::IdentityMode::Current => 0,
        isolation::IdentityMode::Restricted => 1,
        isolation::IdentityMode::AppContainer => 2,
    };
    Ok((policy, resources, container_name, package_id, filesystem_mode, process_mode, network_mode, identity_mode))
}

fn launch_detached_prepared_package(run_dir: &Path, info: &str, args: &[String], run_id: &str, log_path: &Path) -> Result<u32, String> {
    let mounted_volumes = volume::parse_specs(info)?;
    let entry = package_entry(info).ok_or_else(|| "package entry is missing".to_string())?;
    let entry_path = safe_entry_path(run_dir, entry)?;
    let (policy, resources, container_name, _package_id, filesystem_mode, process_mode, network_mode, identity_mode) = launch_parameters(info)?;
    let environment = build_child_environment(info, run_dir, &mounted_volumes)?;
    let exe = entry_path.to_string_lossy().into_owned();
    let cwd = run_dir.to_string_lossy().into_owned();
    let argline = args.iter().map(|a| quote_windows_arg(a)).collect::<Vec<_>>().join(" ");
    let job_name = container_job_name(run_id);
    let exe_c = CString::new(exe).map_err(|_| "invalid executable path".to_string())?;
    let args_c = CString::new(argline).map_err(|_| "invalid argument string".to_string())?;
    let cwd_c = CString::new(cwd).map_err(|_| "invalid working directory".to_string())?;
    let name_c = CString::new(container_name).map_err(|_| "invalid container name".to_string())?;
    let job_c = CString::new(job_name).map_err(|_| "invalid job name".to_string())?;
    let log_c = CString::new(log_path.to_string_lossy().as_bytes()).map_err(|_| "invalid log path".to_string())?;
    let _ = policy;
    let mut pid = 0u32;
    let rc = unsafe {
        ake_spawn_isolated_process_detached(
            exe_c.as_ptr(), args_c.as_ptr(), cwd_c.as_ptr(),
            environment.as_ptr(), environment.len(), name_c.as_ptr(),
            filesystem_mode, process_mode, network_mode, identity_mode,
            resources.memory_bytes, resources.cpu_rate_percent_x100,
            resources.active_processes, resources.process_user_time_100ns,
            job_c.as_ptr(), log_c.as_ptr(), &mut pid,
        )
    };
    if rc != 0 || pid == 0 {
        return Err(format!("native process launch failed with code {rc}"));
    }
    Ok(pid)
}

fn detached_archive_package(package: &str, args: &[String]) -> i32 {
    let package_path = Path::new(package);
    let cpath = match CString::new(package) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid package path"); return 2; }
    };
    let mut info_buf = vec![0i8; 8192];
    let rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
    if rc != 0 {
        let msg = c_string(info_buf.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    let info = c_string(info_buf.as_ptr());
    let id = match metadata_field(&info, "id") {
        Some(v) if !v.is_empty() => v,
        _ => { eprintln!("AKE010: package id is invalid"); return 1; }
    };
    let version = metadata_field(&info, "version").unwrap_or_else(|| "0.0.0".to_string());
    let architecture = metadata_field(&info, "architecture").unwrap_or_default();
    let entry = match package_entry(&info) { Some(v) => v.to_string(), None => { eprintln!("AKE010: package entry is invalid"); return 1; } };

    if let Err(e) = trust::enforce_install_policy(package, trust::Source::Local) { eprintln!("AKE075: {e}"); return 1; }
    let dependencies = match parse_dependencies(&info) { Ok(v) => v, Err(e) => { eprintln!("AKE030: {e}"); return 1; } };
    if let Err(e) = resolve_dependencies(&id, &dependencies) { eprintln!("AKE030: dependency resolution failed: {e}"); return 1; }

    if let Err(e) = runtime_state::prepare() { eprintln!("AKE090: {e}"); return 1; }
    let run_id = runtime_state::new_id();
    let run_dir = match temp_run_directory(package_path) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE011: {e}"); return 1; }
    };
    let run_dir_c = match CString::new(run_dir.to_string_lossy().as_bytes()) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid runtime directory"); return 2; }
    };
    let mut error = vec![0i8; 512];
    let extract_rc = unsafe { ake_extract_package(cpath.as_ptr(), run_dir_c.as_ptr(), error.as_mut_ptr(), error.len()) };
    if extract_rc != 0 {
        let msg = c_string(error.as_ptr());
        let _ = fs::remove_dir_all(&run_dir);
        eprintln!("AKE{:03}: {}", extract_rc, if msg.is_empty() { "package extraction failed" } else { &msg });
        return 1;
    }
    let specs = match volume::parse_specs(&info) {
        Ok(v) => v,
        Err(e) => { let _ = fs::remove_dir_all(&run_dir); eprintln!("AKE018: invalid volume metadata: {e}"); return 1; }
    };
    if let Err(e) = volume::mount_all(&specs, &run_dir) {
        let _ = fs::remove_dir_all(&run_dir);
        eprintln!("AKE018: volume setup failed: {e}");
        return 1;
    }
    let log_path = runtime_state::default_log_path(&run_id);
    let _ = audit::log(audit::RUN_START, "start", &id, &version, &format!("run_id={run_id} mode=detached archive"));
    let pid = match launch_detached_prepared_package(&run_dir, &info, args, &run_id, &log_path) {
        Ok(v) => v,
        Err(e) => { let _ = audit::log(audit::RUN_EXIT, "error", &id, &version, &format!("run_id={run_id} launch_error={e}")); let _ = volume::unmount_all(&specs, &run_dir); let _ = fs::remove_dir_all(&run_dir); eprintln!("AKE012: {e}"); return 1; }
    };
    let record = runtime_state::RunRecord {
        id: run_id.clone(), package_id: id, version, architecture, pid,
        started_unix: now_unix(), status: runtime_state::Status::Running,
        exit_code: None, package_root: run_dir, entry, log_path,
        job_name: container_job_name(&run_id), cleanup_runtime: true,
    };
    if let Err(e) = runtime_state::write(&record) {
        if let Ok(job) = CString::new(record.job_name.clone()) { unsafe { ake_terminate_job_or_process(job.as_ptr(), pid); } }
        let _ = volume::unmount_all(&specs, &record.package_root);
        let _ = fs::remove_dir_all(&record.package_root);
        eprintln!("AKE090: cannot persist runtime state: {e}");
        return 1;
    }
    let _ = audit::log(audit::RUN_START, "ok", &record.package_id, &record.version, &format!("run_id={} pid={} mode=detached", record.id, record.pid));
    println!("Started AKE container {} (pid {})", run_id, pid);
    println!("Log: {}", record.log_path.display());
    0
}

fn detached_installed_package(id: &str, args: &[String]) -> i32 {
    let pkg = match package_db::find(id) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE023: {e}"); return 1; }
    };
    let info = match read_installed_info(&pkg) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE024: {e}"); return 1; }
    };
    if package_entry(&info).unwrap_or("") != pkg.entry {
        eprintln!("AKE024: installed package entry does not match database record");
        return 1;
    }
    if let Err(e) = runtime_state::prepare() { eprintln!("AKE090: {e}"); return 1; }
    let run_id = runtime_state::new_id();
    let entry = pkg.entry.clone();
    let log_path = runtime_state::default_log_path(&run_id);
    let has_volumes = match volume::parse_specs(&info) {
        Ok(v) => !v.is_empty(),
        Err(e) => { eprintln!("AKE018: invalid volume metadata: {e}"); return 1; }
    };
    let (run_dir, _mounted_specs) = if has_volumes {
        match prepare_installed_volume_runtime(&pkg, &info) {
            Ok((dir, specs)) => (dir, specs),
            Err(e) => { eprintln!("AKE018: {e}"); return 1; }
        }
    } else {
        (pkg.install_dir.clone(), Vec::new())
    };
    let _ = audit::log(audit::RUN_START, "start", &pkg.id, &pkg.version, &format!("run_id={run_id} mode=detached installed"));
    let pid = match launch_detached_prepared_package(&run_dir, &info, args, &run_id, &log_path) {
        Ok(v) => v,
        Err(e) => { let _ = audit::log(audit::RUN_EXIT, "error", &pkg.id, &pkg.version, &format!("run_id={run_id} launch_error={e}")); if has_volumes { let specs = volume::parse_specs(&info).unwrap_or_default(); let _ = volume::unmount_all(&specs, &run_dir); let _ = fs::remove_dir_all(&run_dir); } eprintln!("AKE012: {e}"); return 1; }
    };
    let record = runtime_state::RunRecord {
        id: run_id.clone(), package_id: pkg.id.clone(), version: pkg.version.clone(), architecture: pkg.architecture.clone(),
        pid, started_unix: now_unix(), status: runtime_state::Status::Running, exit_code: None,
        package_root: run_dir, entry, log_path, job_name: container_job_name(&run_id), cleanup_runtime: has_volumes,
    };
    if let Err(e) = runtime_state::write(&record) {
        if let Ok(job) = CString::new(record.job_name.clone()) { unsafe { ake_terminate_job_or_process(job.as_ptr(), pid); } }
        if has_volumes { let specs = volume::parse_specs(&info).unwrap_or_default(); let _ = volume::unmount_all(&specs, &record.package_root); let _ = fs::remove_dir_all(&record.package_root); }
        eprintln!("AKE090: cannot persist runtime state: {e}");
        return 1;
    }
    let _ = audit::log(audit::RUN_START, "ok", &record.package_id, &record.version, &format!("run_id={} pid={} mode=detached", record.id, record.pid));
    println!("Started AKE container {} (pid {})", run_id, pid);
    println!("Log: {}", record.log_path.display());
    0
}

fn cleanup_runtime_if_needed(record: &runtime_state::RunRecord) {
    if record.cleanup_runtime {
        if let Ok(info) = fs::read_to_string(record.package_root.join("metadata").join("package.ake")) {
            if let Ok(specs) = volume::parse_specs(&info) {
                let _ = volume::unmount_all(&specs, &record.package_root);
            }
        }
        let _ = fs::remove_dir_all(&record.package_root);
    }
}

fn refresh_record(mut record: runtime_state::RunRecord) -> runtime_state::RunRecord {
    if !matches!(record.status, runtime_state::Status::Running | runtime_state::Status::Stopping) {
        return record;
    }
    let mut running = 0i32;
    let mut code = 0i32;
    let Ok(pid_c) = u32::try_from(record.pid) else { return record; };
    let rc = unsafe { ake_query_process(pid_c, &mut running, &mut code) };
    if rc != 0 || running != 0 { return record; }
    if record.status == runtime_state::Status::Stopping {
        record.status = runtime_state::Status::Stopped;
    } else {
        record.status = runtime_state::Status::Exited;
    }
    record.exit_code = Some(code);
    let status_name = record.status.as_str();
    let _ = audit::log(audit::RUN_EXIT, if code == 0 { "ok" } else { "error" }, &record.package_id, &record.version, &format!("run_id={} status={} exit_code={}", record.id, status_name, code));
    cleanup_runtime_if_needed(&record);
    let _ = runtime_state::update(&record);
    record
}

fn list_processes(all: bool) -> i32 {
    let records = match runtime_state::list() { Ok(v) => v, Err(e) => { eprintln!("AKE090: {e}"); return 1; } };
    println!("{:<22} {:<8} {:<10} {:<16} {}", "RUN ID", "PID", "STATUS", "PACKAGE", "VERSION");
    let mut shown = 0usize;
    for record in records {
        let record = refresh_record(record);
        if !all && !matches!(record.status, runtime_state::Status::Running | runtime_state::Status::Stopping) { continue; }
        println!("{:<22} {:<8} {:<10} {:<16} {}", record.id, record.pid, record.status.as_str(), record.package_id, record.version);
        shown += 1;
    }
    if shown == 0 { println!("(no AKE containers)"); }
    0
}

fn logs_command(id: &str, tail: Option<usize>) -> i32 {
    let record = match runtime_state::find(id) { Ok(v) => v, Err(e) => { eprintln!("AKE090: {e}"); return 1; } };
    let record = refresh_record(record);
    let text = match tail { Some(n) => runtime_state::tail_lines(&record, n), None => runtime_state::read_logs(&record) };
    match text {
        Ok(value) => { print!("{value}"); 0 }
        Err(e) => { eprintln!("AKE091: {e}"); 1 }
    }
}

fn stop_command(id: &str) -> i32 {
    let mut record = match runtime_state::find(id) { Ok(v) => v, Err(e) => { eprintln!("AKE090: {e}"); return 1; } };
    record = refresh_record(record);
    if !matches!(record.status, runtime_state::Status::Running | runtime_state::Status::Stopping) {
        eprintln!("AKE092: container is not running");
        return 1;
    }
    let job_c = match CString::new(record.job_name.clone()) { Ok(v) => v, Err(_) => { eprintln!("AKE002: invalid job name"); return 2; } };
    let rc = unsafe { ake_terminate_job_or_process(job_c.as_ptr(), record.pid) };
    if rc != 0 { eprintln!("AKE093: stop failed with code {rc}"); return 1; }
    record.status = runtime_state::Status::Stopping;
    if let Err(e) = runtime_state::update(&record) { eprintln!("AKE090: {e}"); return 1; }
    let _ = audit::log(audit::RUN_STOP, "ok", &record.package_id, &record.version, id);
    println!("Stopping AKE container {}", id);
    0
}

fn run_archive_package(package: &str, args: &[String]) -> i32 {
    let package_path = Path::new(package);
    let cpath = match CString::new(package) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid package path"); return 2; }
    };
    let mut info_buf = vec![0i8; 8192];
    let rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
    if rc != 0 {
        let msg = c_string(info_buf.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    let info = c_string(info_buf.as_ptr());

    let run_dir = match temp_run_directory(package_path) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE011: {e}"); return 1; }
    };
    let run_dir_str = run_dir.to_string_lossy().into_owned();
    let dest_c = match CString::new(run_dir_str) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid runtime directory"); return 2; }
    };
    let mut extract_error = vec![0i8; 512];
    let extract_rc = unsafe { ake_extract_package(cpath.as_ptr(), dest_c.as_ptr(), extract_error.as_mut_ptr(), extract_error.len()) };
    if extract_rc != 0 {
        let msg = c_string(extract_error.as_ptr());
        let _ = fs::remove_dir_all(&run_dir);
        eprintln!("AKE{:03}: {}", extract_rc, if msg.is_empty() { "package extraction failed" } else { &msg });
        return 1;
    }

    let specs = match volume::parse_specs(&info) {
        Ok(v) => v,
        Err(e) => { let _ = fs::remove_dir_all(&run_dir); eprintln!("AKE018: invalid volume metadata: {e}"); return 1; }
    };
    if let Err(e) = volume::mount_all(&specs, &run_dir) {
        let _ = fs::remove_dir_all(&run_dir);
        eprintln!("AKE018: volume setup failed: {e}");
        return 1;
    }
    let status = launch_prepared_package(&run_dir, &info, args, &specs);
    let _ = volume::unmount_all(&specs, &run_dir);
    if fs::remove_dir_all(&run_dir).is_err() {
        eprintln!("AKE013: failed to remove runtime directory");
        if status == 0 { return 1; }
    }
    status
}

pub(crate) fn read_installed_info(pkg: &package_db::InstalledPackage) -> Result<String, String> {
    let root = package_db::root().join("packages");
    let package_root = pkg.install_dir.canonicalize().map_err(|e| format!("installed package directory is missing: {e}"))?;
    let allowed_root = root.canonicalize().map_err(|e| format!("cannot resolve AKE package root: {e}"))?;
    if !package_root.starts_with(&allowed_root) {
        return Err("installed package path is outside AKE package root".to_string());
    }
    if !package_root.is_dir() {
        return Err("installed package directory is not a directory".to_string());
    }
    let metadata = package_root.join("metadata").join("package.ake");
    let text = fs::read_to_string(&metadata).map_err(|e| format!("cannot read installed package metadata: {e}"))?;
    Ok(text)
}

fn run_installed_package(id: &str, args: &[String]) -> i32 {
    let pkg = match package_db::find(id) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE023: {e}"); return 1; }
    };
    let info = match read_installed_info(&pkg) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE024: {e}"); return 1; }
    };
    let db_entry = package_entry(&info).unwrap_or("");
    if db_entry != pkg.entry {
        eprintln!("AKE024: installed package entry does not match database record");
        return 1;
    }
    let has_volumes = match volume::parse_specs(&info) {
        Ok(v) => !v.is_empty(),
        Err(e) => { eprintln!("AKE018: invalid volume metadata: {e}"); return 1; }
    };
    if has_volumes {
        let (run_dir, specs) = match prepare_installed_volume_runtime(&pkg, &info) {
            Ok(v) => v,
            Err(e) => { eprintln!("AKE018: {e}"); return 1; }
        };
        let _ = audit::log(audit::RUN_START, "ok", &pkg.id, &pkg.version, "mode=foreground volume-runtime");
        let status = launch_prepared_package(&run_dir, &info, args, &specs);
        let _ = audit::log(audit::RUN_EXIT, if status == 0 { "ok" } else { "error" }, &pkg.id, &pkg.version, &format!("mode=foreground exit_code={status}"));
        let _ = volume::unmount_all(&specs, &run_dir);
        let _ = fs::remove_dir_all(&run_dir);
        status
    } else {
        let _ = audit::log(audit::RUN_START, "ok", &pkg.id, &pkg.version, "mode=foreground installed");
        let status = launch_prepared_package(&pkg.install_dir, &info, args, &[]);
        let _ = audit::log(audit::RUN_EXIT, if status == 0 { "ok" } else { "error" }, &pkg.id, &pkg.version, &format!("mode=foreground exit_code={status}"));
        status
    }
}

fn run_package(package_or_id: &str, args: &[String]) -> i32 {
    let path = Path::new(package_or_id);
    if path.extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("ake")).unwrap_or(false) {
        if !path.is_file() {
            eprintln!("AKE002: package file does not exist: {}", package_or_id);
            return 2;
        }
        return run_archive_package(package_or_id, args);
    }
    run_installed_package(package_or_id, args)
}


fn dependency_id_valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| {
        matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_')
    })
}

fn parse_dependencies(info: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for line in info.lines().filter(|line| line.starts_with("dependency=")) {
        let expr = &line[11..];
        if expr.is_empty() {
            return Err("empty dependency expression".to_string());
        }
        let op_pos = expr.find(|c: char| matches!(c, '>' | '<' | '='));
        let (id, constraint) = match op_pos {
            Some(pos) => (&expr[..pos], expr[pos..].trim().to_string()),
            None => (expr, "*".to_string()),
        };
        if !dependency_id_valid(id) {
            return Err(format!("invalid dependency package id: {id}"));
        }
        if constraint != "*" {
            let valid_op = constraint.starts_with('=') || constraint.starts_with('>') || constraint.starts_with('<');
            if !valid_op {
                return Err(format!("invalid dependency constraint: {constraint}"));
            }
            let version = constraint.trim_start_matches(|c: char| matches!(c, '>' | '<' | '='));
            if version.is_empty() || version.len() > 128 || version.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'.' | b'-' | b'+' | b'A'..=b'Z' | b'a'..=b'z')) {
                return Err(format!("invalid dependency version: {version}"));
            }
        }
        out.push((id.to_string(), constraint));
    }
    Ok(out)
}

fn version_parts(version: &str) -> Vec<u64> {
    let core = version.split_once('-').map(|x| x.0).unwrap_or(version);
    let core = core.split_once('+').map(|x| x.0).unwrap_or(core);
    core.split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

fn prerelease(version: &str) -> Option<&str> {
    let coreless = version.split_once('+').map(|x| x.0).unwrap_or(version);
    coreless.split_once('-').map(|x| x.1)
}

fn compare_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    let aa: Vec<&str> = a.split('.').collect();
    let bb: Vec<&str> = b.split('.').collect();
    for i in 0..aa.len().max(bb.len()) {
        let left = aa.get(i);
        let right = bb.get(i);
        match (left, right) {
            (None, None) => break,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                let xn = x.parse::<u64>();
                let yn = y.parse::<u64>();
                match (xn, yn) {
                    (Ok(xv), Ok(yv)) => match xv.cmp(&yv) {
                        std::cmp::Ordering::Equal => {}
                        other => return other,
                    },
                    (Ok(_), Err(_)) => return std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => return std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => match x.cmp(y) {
                        std::cmp::Ordering::Equal => {}
                        other => return other,
                    },
                }
            }
        }
    }
    std::cmp::Ordering::Equal
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let aa = version_parts(a);
    let bb = version_parts(b);
    let n = aa.len().max(bb.len());
    for i in 0..n {
        let av = *aa.get(i).unwrap_or(&0);
        let bv = *bb.get(i).unwrap_or(&0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    match (prerelease(a), prerelease(b)) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => compare_prerelease(x, y),
    }
}

fn version_satisfies(version: &str, constraint: &str) -> bool {
    if constraint.is_empty() || constraint == "*" {
        return true;
    }
    let (op, wanted) = if let Some(v) = constraint.strip_prefix(">=") {
        (">=", v)
    } else if let Some(v) = constraint.strip_prefix("<=") {
        ("<=", v)
    } else if let Some(v) = constraint.strip_prefix('>') {
        (">", v)
    } else if let Some(v) = constraint.strip_prefix('<') {
        ("<", v)
    } else if let Some(v) = constraint.strip_prefix('=') {
        ("=", v)
    } else {
        return false;
    };
    match compare_versions(version, wanted) {
        std::cmp::Ordering::Equal => matches!(op, ">=" | "<=" | "="),
        std::cmp::Ordering::Greater => matches!(op, ">=" | ">"),
        std::cmp::Ordering::Less => matches!(op, "<=" | "<"),
    }
}

fn resolve_installed_dependency(id: &str, constraint: &str, trail: &mut Vec<String>) -> Result<(), String> {
    let pkg = package_db::find(id).map_err(|_| format!("missing dependency: {id}{constraint}"))?;
    if !version_satisfies(&pkg.version, constraint) {
        return Err(format!("dependency {id}{} is not satisfied by installed version {}", constraint, pkg.version));
    }
    if trail.iter().any(|x| x == id) {
        let mut cycle = trail.clone();
        cycle.push(id.to_string());
        return Err(format!("dependency cycle detected: {}", cycle.join(" -> ")));
    }
    trail.push(id.to_string());
    for (dep_id, dep_constraint) in &pkg.dependencies {
        resolve_installed_dependency(dep_id, dep_constraint, trail)?;
    }
    trail.pop();
    Ok(())
}

fn resolve_dependencies(root_id: &str, dependencies: &[(String, String)]) -> Result<(), String> {
    for (dep_id, constraint) in dependencies {
        if dep_id == root_id {
            return Err(format!("package cannot depend on itself: {root_id}"));
        }
        let mut trail = vec![root_id.to_string()];
        resolve_installed_dependency(dep_id, constraint, &mut trail)?;
    }
    Ok(())
}

pub(crate) fn audit_pkg(info: &str) -> (String, String) {
    (metadata_field(info, "id").unwrap_or_default(), metadata_field(info, "version").unwrap_or_default())
}

fn metadata_field(info: &str, key: &str) -> Option<String> {
    info.lines().find_map(|line| {
        line.strip_prefix(key).and_then(|value| value.strip_prefix('='))
            .map(|value| value.to_string())
    })
}


fn current_architecture() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { return "x64"; }
    #[cfg(target_arch = "x86")]
    { return "x86"; }
    #[cfg(target_arch = "aarch64")]
    { return "arm64"; }
    "unknown"
}

fn install_repository_package(id: &str) -> Result<(), String> {
    if !dependency_id_valid(id) {
        return Err("invalid package id".to_string());
    }
    let arch = current_architecture();
    let mut visiting = Vec::<String>::new();
    let mut installed_this_run = Vec::<String>::new();
    install_repository_recursive(id, "*", arch, &mut visiting, &mut installed_this_run)
}

fn install_repository_recursive(
    id: &str,
    constraint: &str,
    architecture: &str,
    visiting: &mut Vec<String>,
    installed_this_run: &mut Vec<String>,
) -> Result<(), String> {
    if let Ok(existing) = package_db::find(id) {
        if version_satisfies(&existing.version, constraint) {
            return Ok(());
        }
        return Err(format!("installed dependency {id}{} does not satisfy requested version {}", constraint, existing.version));
    }
    if visiting.iter().any(|x| x == id) {
        let mut cycle = visiting.clone();
        cycle.push(id.to_string());
        return Err(format!("repository dependency cycle detected: {}", cycle.join(" -> ")));
    }
    visiting.push(id.to_string());

    let record = repository::find_best(id, constraint, architecture)?;
    let package = repository::download_package(&record)?;
    let signature_downloaded = match repository::download_signature(&record, &package) {
        Ok(value) => value,
        Err(e) => { let _ = fs::remove_file(&package); return Err(e); }
    };
    let package_result = (|| -> Result<(), String> {
        let cpath = CString::new(package.to_string_lossy().as_bytes()).map_err(|_| "invalid downloaded package path".to_string())?;
        let mut info_buf = vec![0i8; 8192];
        let rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
        if rc != 0 {
            return Err(format!("downloaded repository package failed AKE validation (code {rc})"));
        }
        let info = c_string(info_buf.as_ptr());
        let package_id = metadata_field(&info, "id").ok_or_else(|| "repository package has no id".to_string())?;
        if package_id != id {
            return Err(format!("repository package identity mismatch: requested {id}, got {package_id}"));
        }
        let version = metadata_field(&info, "version").ok_or_else(|| "repository package has no version".to_string())?;
        if !version_satisfies(&version, constraint) {
            return Err(format!("repository package version {version} does not satisfy {constraint}"));
        }
        let signer = trust::enforce_install_policy(&package.to_string_lossy(), trust::Source::Repository)?;
        if let Some(signer) = signer { println!("Trusted signer: {signer}"); }
        let dependencies = parse_dependencies(&info).map_err(|e| format!("invalid package dependencies: {e}"))?;
        for (dep_id, dep_constraint) in &dependencies {
            install_repository_recursive(dep_id, dep_constraint, architecture, visiting, installed_this_run)?;
        }

        let rc_install = install(&package.to_string_lossy());
        if rc_install != 0 {
            return Err(format!("failed to install repository package {id} {version}"));
        }
        installed_this_run.push(id.to_string());
        println!("Repository: {}", record.repository);
        Ok(())
    })();
    let _ = fs::remove_file(&package);
    if signature_downloaded { let _ = fs::remove_file(PathBuf::from(format!("{}.sig", package.display()))); }
    visiting.pop();
    package_result
}

fn repository_command(args: &[String]) -> i32 {
    if args.len() < 2 {
        print_help();
        return 2;
    }
    match args[1].as_str() {
        "add" if args.len() == 4 => match repository::add(&args[2], &args[3]) {
            Ok(()) => { println!("Repository added: {} -> {}", args[2], args[3]); 0 }
            Err(e) => { eprintln!("AKE050: {e}"); 1 }
        },
        "remove" if args.len() == 3 => match repository::remove(&args[2]) {
            Ok(()) => { println!("Repository removed: {}", args[2]); 0 }
            Err(e) => { eprintln!("AKE050: {e}"); 1 }
        },
        "list" if args.len() == 2 => match repository::list() {
            Ok(repos) => {
                if repos.is_empty() { println!("No repositories configured."); }
                else { for repo in repos { println!("{}\t{}", repo.name, repo.url); } }
                0
            }
            Err(e) => { eprintln!("AKE050: {e}"); 1 }
        },
        _ => { print_help(); 2 }
    }
}

fn search_repository(term: &str) -> i32 {
    match repository::search(term) {
        Ok(entries) => { repository::print_search(&entries); 0 }
        Err(e) => { eprintln!("AKE051: {e}"); 1 }
    }
}


fn trust_command(args: &[String]) -> i32 {
    if args.len() < 2 {
        print_help();
        return 2;
    }
    match args[1].as_str() {
        "add" if args.len() == 3 || args.len() == 4 => {
            let path = Path::new(&args[2]);
            let ext_ok = path.extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("akepub")).unwrap_or(false);
            if !ext_ok {
                eprintln!("AKE070: trusted public key must use .akepub extension");
                return 2;
            }
            match trust::add(&args[2], args.get(3).map(String::as_str)) {
                Ok(key_id) => { let _ = audit::log(audit::TRUST_ACCEPTED, "ok", "", "", &format!("key={key_id}")); println!("Trusted key added: {key_id}"); 0 }
                Err(e) => { let _ = audit::log(audit::TRUST_REJECTED, "error", "", "", &e); eprintln!("AKE070: {e}"); 1 }
            }
        }
        "remove" if args.len() == 3 => match trust::remove(&args[2]) {
            Ok(()) => { println!("Trusted key removed: {}", args[2]); 0 }
            Err(e) => { eprintln!("AKE071: {e}"); 1 }
        },
        "list" if args.len() == 2 => match trust::list() {
            Ok(keys) => {
                if keys.is_empty() {
                    println!("No trusted AKE keys.");
                    println!("Trust store: {}", trust::root().display());
                } else {
                    println!("{:<66} NAME", "KEY ID");
                    for key in keys { println!("{:<66} {}", key.key_id, key.name); }
                }
                0
            }
            Err(e) => { eprintln!("AKE072: {e}"); 1 }
        },
        "verify" if args.len() == 3 || args.len() == 4 => match trust::verify_trusted(&args[2], args.get(3).map(String::as_str)) {
            Ok(signer) => { let _ = audit::log(audit::TRUST_ACCEPTED, "ok", "", "", &format!("package={} signer={}", args[2], signer)); println!("Trusted AKE signature: {}", signer); 0 }
            Err(e) => { let _ = audit::log(audit::TRUST_REJECTED, "error", "", "", &format!("package={} error={}", args[2], e)); eprintln!("AKE073: {e}"); 1 }
        },
        "policy" if args.len() == 2 => match trust::policy() {
            Ok((local, repository)) => {
                println!("local={local}");
                println!("repository={repository}");
                0
            }
            Err(e) => { eprintln!("AKE074: {e}"); 1 }
        },
        "policy" if args.len() == 5 && args[2] == "set" => match trust::set_policy(&args[3], &args[4]) {
            Ok(()) => { println!("Trust policy updated: {}={}", args[3], args[4]); 0 }
            Err(e) => { eprintln!("AKE074: {e}"); 1 }
        },
        _ => { print_help(); 2 }
    }
}

fn install(path: &str) -> i32 {
    if !Path::new(path).extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("ake")).unwrap_or(false) {
        match install_repository_package(path) {
            Ok(()) => { println!("Installed repository package: {path}"); return 0; }
            Err(e) => { eprintln!("AKE052: {e}"); return 1; }
        }
    }
    let cpath = match CString::new(path) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid package path"); return 2; }
    };
    let mut info_buf = vec![0i8; 8192];
    let rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
    if rc != 0 {
        let msg = c_string(info_buf.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    let info = c_string(info_buf.as_ptr());
    let id = match metadata_field(&info, "id") {
        Some(v) if !v.is_empty() => v,
        _ => { eprintln!("AKE010: package id is invalid"); return 1; }
    };
    let version = match metadata_field(&info, "version") {
        Some(v) if !v.is_empty() => v,
        _ => { eprintln!("AKE010: package version is invalid"); return 1; }
    };
    let architecture = metadata_field(&info, "architecture").unwrap_or_default();
    let name = metadata_field(&info, "name").unwrap_or_else(|| id.clone());
    let entry = match package_entry(&info) {
        Some(v) => v.to_string(),
        None => { eprintln!("AKE010: package entry is invalid"); return 1; }
    };
    let _ = audit::log(audit::INSTALL_BEGIN, "start", &id, &version, path);
    let signature_signer = match trust::enforce_install_policy(path, trust::Source::Local) {
        Ok(v) => v,
        Err(e) => { let _ = audit::log(audit::POLICY_DENIED, "denied", &id, &version, &format!("install trust policy: {e}")); eprintln!("AKE075: {e}"); return 1; }
    };
    let dependencies = match parse_dependencies(&info) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE030: {e}"); return 1; }
    };
    if let Err(e) = resolve_dependencies(&id, &dependencies) {
        eprintln!("AKE030: dependency resolution failed: {e}");
        return 1;
    }

    let install_result = package_db::install(&id, &version, &architecture, &name, &entry, &dependencies, |destination| {
        let d = CString::new(destination.to_string_lossy().as_bytes()).map_err(|_| "invalid installation path".to_string())?;
        let mut error = vec![0i8; 512];
        let rc = unsafe { ake_extract_package(cpath.as_ptr(), d.as_ptr(), error.as_mut_ptr(), error.len()) };
        if rc != 0 {
            let msg = c_string(error.as_ptr());
            return Err(format!("AKE{:03}: {}", rc, if msg.is_empty() { "package extraction failed" } else { &msg }));
        }
        Ok(())
    });

    match install_result {
        Ok(pkg) => {
            let installed_info = match read_installed_info(&pkg) {
                Ok(v) => v,
                Err(e) => { let _ = package_db::remove(&pkg.id); eprintln!("AKE026: cannot read installed metadata: {e}"); return 1; }
            };
            if let Err(e) = windows_integration::install(&pkg.id, &pkg.install_dir, &installed_info) {
                let _ = package_db::remove(&pkg.id);
                eprintln!("AKE026: Windows integration failed; installation rolled back: {e}");
                return 1;
            }
            if let Err(e) = service::install(&pkg.id, &pkg.install_dir, &installed_info) {
                let _ = windows_integration::remove(&pkg.id, &installed_info);
                let _ = package_db::remove(&pkg.id);
                eprintln!("AKE027: Windows service installation failed; installation rolled back: {e}");
                return 1;
            }
            println!("Installed {} {}", pkg.id, pkg.version);
            if let Some(signer) = signature_signer.as_deref() { println!("Trusted signer: {signer}"); }
            let _ = audit::log(audit::INSTALL_OK, "ok", &pkg.id, &pkg.version, pkg.install_dir.to_string_lossy().as_ref());
            println!("Location: {}", pkg.install_dir.display());
            0
        }
        Err(e) => {
            let _ = audit::log(audit::INSTALL_FAIL, "error", &id, &version, &e);
            eprintln!("AKE020: {e}"); 1
        }
    }
}


fn update_package(path: &str) -> i32 {
    if !Path::new(path).extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("ake")).unwrap_or(false) {
        eprintln!("AKE002: package extension must be .ake");
        return 2;
    }
    let cpath = match CString::new(path) {
        Ok(v) => v,
        Err(_) => { eprintln!("AKE002: invalid package path"); return 2; }
    };
    let mut info_buf = vec![0i8; 8192];
    let rc = unsafe { ake_package_info(cpath.as_ptr(), info_buf.as_mut_ptr(), info_buf.len()) };
    if rc != 0 {
        let msg = c_string(info_buf.as_ptr());
        eprintln!("AKE{:03}: {}", rc, if msg.is_empty() { "invalid package" } else { &msg });
        return 1;
    }
    let info = c_string(info_buf.as_ptr());
    let id = match metadata_field(&info, "id") {
        Some(v) if !v.is_empty() => v,
        _ => { eprintln!("AKE010: package id is invalid"); return 1; }
    };
    let version = match metadata_field(&info, "version") {
        Some(v) if !v.is_empty() => v,
        _ => { eprintln!("AKE010: package version is invalid"); return 1; }
    };
    let architecture = metadata_field(&info, "architecture").unwrap_or_default();
    let name = metadata_field(&info, "name").unwrap_or_else(|| id.clone());
    let entry = match package_entry(&info) {
        Some(v) => v.to_string(),
        None => { eprintln!("AKE010: package entry is invalid"); return 1; }
    };
    let _ = audit::log(audit::UPDATE_BEGIN, "start", &id, &version, path);
    let signature_signer = match trust::enforce_install_policy(path, trust::Source::Local) {
        Ok(v) => v,
        Err(e) => { let _ = audit::log(audit::POLICY_DENIED, "denied", &id, &version, &format!("install trust policy: {e}")); eprintln!("AKE075: {e}"); return 1; }
    };
    let dependencies = match parse_dependencies(&info) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE030: {e}"); return 1; }
    };
    if let Err(e) = resolve_dependencies(&id, &dependencies) {
        eprintln!("AKE030: dependency resolution failed: {e}");
        return 1;
    }

    let old_pkg = match package_db::find(&id) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE025: {e}"); return 1; }
    };
    let old_info = read_installed_info(&old_pkg).unwrap_or_default();

    let result = package_db::update(&id, &version, &architecture, &name, &entry, &dependencies, |destination| {
        let d = CString::new(destination.to_string_lossy().as_bytes())
            .map_err(|_| "invalid update staging path".to_string())?;
        let mut error = vec![0i8; 512];
        let rc = unsafe { ake_extract_package(cpath.as_ptr(), d.as_ptr(), error.as_mut_ptr(), error.len()) };
        if rc != 0 {
            let msg = c_string(error.as_ptr());
            return Err(format!("AKE{:03}: {}", rc, if msg.is_empty() { "package extraction failed" } else { &msg }));
        }
        Ok(())
    });

    match result {
        Ok((old, new, stale_old)) => {
            let _ = service::remove(&old.id, &old_info);
            let _ = windows_integration::remove(&old.id, &old_info);
            let new_info = match read_installed_info(&new) {
                Ok(v) => v,
                Err(e) => { eprintln!("AKE026: updated package metadata unavailable: {e}"); return 1; }
            };
            if let Err(e) = windows_integration::install(&new.id, &new.install_dir, &new_info) {
                let _ = windows_integration::install(&old.id, &new.install_dir, &old_info);
                eprintln!("AKE026: Windows integration update failed: {e}");
                return 1;
            }
            if let Err(e) = service::install(&new.id, &new.install_dir, &new_info) {
                let _ = windows_integration::remove(&new.id, &new_info);
                let _ = service::install(&old.id, &new.install_dir, &old_info);
                let _ = windows_integration::install(&old.id, &new.install_dir, &old_info);
                eprintln!("AKE027: Windows service update failed: {e}");
                return 1;
            }
            println!("Updated {} {} -> {}", new.id, old.version, new.version);
            if let Some(signer) = signature_signer.as_deref() { println!("Trusted signer: {signer}"); }
            println!("Location: {}", new.install_dir.display());
            if stale_old {
                eprintln!("AKE025: old version {} could not be removed; it remains as an orphaned version directory", old.version);
            }
            let _ = audit::log(audit::UPDATE_OK, "ok", &new.id, &new.version, &format!("from={}", old.version));
            0
        }
        Err(e) => {
            let _ = audit::log(audit::UPDATE_FAIL, "error", &id, &version, &e);
            eprintln!("AKE025: {e}"); 1
        }
    }
}

fn remove_package(id: &str) -> i32 {
    if id.is_empty() || id.contains('\0') {
        eprintln!("AKE002: invalid package id");
        return 2;
    }
    let pkg = match package_db::find(id) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE021: {e}"); return 1; }
    };
    let installed_info = match read_installed_info(&pkg) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE021: cannot read installed metadata: {e}"); return 1; }
    };
    if let Err(e) = service::remove(id, &installed_info) {
        eprintln!("AKE027: Windows service removal failed: {e}");
        return 1;
    }
    if let Err(e) = windows_integration::remove(id, &installed_info) {
        eprintln!("AKE026: Windows integration removal failed: {e}");
        return 1;
    }
    match package_db::remove(id) {
        Ok(pkg) => {
            let _ = audit::log(audit::REMOVE_OK, "ok", &pkg.id, &pkg.version, "removed");
            println!("Removed {} {}", pkg.id, pkg.version);
            0
        }
        Err(e) => {
            let _ = audit::log(audit::REMOVE_FAIL, "error", id, "", &e);
            eprintln!("AKE021: {e}"); 1
        }
    }
}

fn list_installed() -> i32 {
    match package_db::list() {
        Ok(packages) => {
            if packages.is_empty() {
                println!("No AKE packages are installed.");
                println!("Database: {}", package_db::root().display());
                return 0;
            }
            println!("{:<32} {:<16} {:<10} NAME", "ID", "VERSION", "ARCH");
            for pkg in packages {
                println!("{:<32} {:<16} {:<10} {}", pkg.id, pkg.version, pkg.architecture, pkg.name);
            }
            0
        }
        Err(e) => { eprintln!("AKE022: {e}"); 1 }
    }
}

fn which_package(id: &str) -> i32 {
    match package_db::find(id) {
        Ok(pkg) => {
            println!("id={}", pkg.id);
            println!("version={}", pkg.version);
            println!("architecture={}", pkg.architecture);
            println!("name={}", pkg.name);
            println!("entry={}", pkg.entry);
            println!("location={}", pkg.install_dir.display());
            0
        }
        Err(e) => { eprintln!("AKE023: {e}"); 1 }
    }
}


fn load_info_target(target: &str) -> Result<String, String> {
    let path = Path::new(target);
    if path.extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("ake")).unwrap_or(false) {
        let c = CString::new(target).map_err(|_| "invalid package path".to_string())?;
        let mut out = vec![0i8; 8192];
        let rc = unsafe { ake_package_info(c.as_ptr(), out.as_mut_ptr(), out.len()) };
        if rc != 0 { return Err(c_string(out.as_ptr())); }
        return Ok(c_string(out.as_ptr()));
    }
    let pkg = package_db::find(target)?;
    read_installed_info(&pkg)
}

fn ports_command(target: &str) -> i32 {
    match load_info_target(target).and_then(|info| ipc::parse_specs(&info)) {
        Ok(specs) => {
            print!("{}", ipc::format_table(&specs));
            0
        }
        Err(e) => { eprintln!("AKE019: {e}"); 1 }
    }
}

fn ipc_command(args: &[String]) -> i32 {
    if args.len() < 2 { print_help(); return 2; }
    match args[1].as_str() {
        "name" if args.len() == 4 => {
            match ipc::validate_component(&args[2]).and_then(|_| ipc::validate_component(&args[3])).and_then(|_| container_pipe_name(&args[2], &args[3])) {
                Ok(name) => { println!("{name}"); 0 },
                Err(e) => { eprintln!("AKE110: {e}"); 1 },
            }
        }
        "serve" if args.len() == 5 || args.len() == 6 => {
            let timeout = if args.len() == 6 { match args[5].parse::<u32>() { Ok(v) => v, Err(_) => { eprintln!("AKE110: invalid timeout"); return 2; } } } else { 30000 };
            let pipe = match ipc::validate_component(&args[2]).and_then(|_| ipc::validate_component(&args[3])).and_then(|_| container_pipe_name(&args[2], &args[3])) {
                Ok(v) => v, Err(e) => { eprintln!("AKE110: {e}"); return 1; }
            };
            let p = match CString::new(pipe) { Ok(v) => v, Err(_) => { eprintln!("AKE110: invalid pipe name"); return 2; } };
            let response = args[4].as_bytes();
            let rc = unsafe { ake_ipc_server_once(p.as_ptr(), response.as_ptr(), response.len(), timeout) };
            if rc != 0 { eprintln!("AKE111: IPC server failed with code {rc}"); 1 } else { println!("IPC request served"); 0 }
        }
        "call" if args.len() == 4 || args.len() == 5 => {
            let timeout = if args.len() == 5 { match args[4].parse::<u32>() { Ok(v) => v, Err(_) => { eprintln!("AKE110: invalid timeout"); return 2; } } } else { 5000 };
            let pipe = match CString::new(args[2].as_str()) { Ok(v) => v, Err(_) => { eprintln!("AKE110: invalid pipe name"); return 2; } };
            let request = args[3].as_bytes();
            let mut response = vec![0u8; 1024 * 1024];
            let mut response_size = 0usize;
            let rc = unsafe { ake_ipc_client_call(pipe.as_ptr(), request.as_ptr(), request.len(), response.as_mut_ptr(), response.len(), &mut response_size, timeout) };
            if rc != 0 { eprintln!("AKE112: IPC call failed with code {rc}"); return 1; }
            match std::str::from_utf8(&response[..response_size]) {
                Ok(v) => print!("{v}"),
                Err(_) => eprintln!("AKE112: IPC response is not UTF-8"),
            }
            0
        }
        _ => { print_help(); 2 }
    }
}


fn integration_command(args: &[String]) -> i32 {
    if args.len() != 3 && args.len() != 4 { print_help(); return 2; }
    let action = args[1].as_str();
    if action == "status" || action == "install" || action == "remove" {
        if args.len() != 3 { print_help(); return 2; }
    } else { print_help(); return 2; }
    let id = &args[2];
    let pkg = match package_db::find(id) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE026: {e}"); return 1; }
    };
    let info = match read_installed_info(&pkg) {
        Ok(v) => v,
        Err(e) => { eprintln!("AKE026: {e}"); return 1; }
    };
    match action {
        "install" => match windows_integration::install(id, &pkg.install_dir, &info) {
            Ok(()) => { println!("Windows integration installed: {id}"); 0 }
            Err(e) => { eprintln!("AKE026: {e}"); 1 }
        },
        "remove" => match windows_integration::remove(id, &info) {
            Ok(()) => { println!("Windows integration removed: {id}"); 0 }
            Err(e) => { eprintln!("AKE026: {e}"); 1 }
        },
        "status" => match windows_integration::status(id, &info) {
            Ok(lines) => { for line in lines { println!("{line}"); } 0 }
            Err(e) => { eprintln!("AKE026: {e}"); 1 }
        },
        _ => 2,
    }
}

fn service_command(args: &[String]) -> i32 {
    if args.len() < 2 { print_help(); return 2; }
    match args[1].as_str() {
        "install" | "remove" | "start" | "stop" | "status" if args.len() == 3 => {
            let id = &args[2];
            let pkg = match package_db::find(id) { Ok(v) => v, Err(e) => { eprintln!("AKE027: {e}"); return 1; } };
            let info = match read_installed_info(&pkg) { Ok(v) => v, Err(e) => { eprintln!("AKE027: {e}"); return 1; } };
            match args[1].as_str() {
                "install" => match service::install(id, &pkg.install_dir, &info) { Ok(()) => { println!("AKE service installed: {id}"); 0 }, Err(e) => { eprintln!("AKE027: {e}"); 1 } },
                "remove" => match service::remove(id, &info) { Ok(()) => { println!("AKE service removed: {id}"); 0 }, Err(e) => { eprintln!("AKE027: {e}"); 1 } },
                "start" => match service::start(id, &info) { Ok(()) => { println!("AKE service started: {id}"); 0 }, Err(e) => { eprintln!("AKE027: {e}"); 1 } },
                "stop" => match service::stop(id, &info) { Ok(()) => { println!("AKE service stopped: {id}"); 0 }, Err(e) => { eprintln!("AKE027: {e}"); 1 } },
                "status" => match service::status(id, &info) { Ok(v) => { println!("{v}"); 0 }, Err(e) => { eprintln!("AKE027: {e}"); 1 } },
                _ => 2,
            }
        }
        "host" if args.len() == 3 => service::host(&args[2]),
        _ => { print_help(); 2 }
    }
}

fn volume_command(args: &[String]) -> i32 {
    if args.len() < 2 { print_help(); return 2; }
    match args[1].as_str() {
        "create" if args.len() == 3 => match volume::create(&args[2]) {
            Ok(path) => { println!("Created AKE volume: {}", path.display()); 0 }
            Err(e) => { eprintln!("AKE100: {e}"); 1 }
        },
        "list" if args.len() == 2 => match volume::list() {
            Ok(names) => { if names.is_empty() { println!("No AKE volumes."); } else { for n in names { println!("{n}"); } } 0 }
            Err(e) => { eprintln!("AKE101: {e}"); 1 }
        },
        "remove" if args.len() == 3 => match volume::remove(&args[2]) {
            Ok(()) => { println!("Removed AKE volume: {}", args[2]); 0 }
            Err(e) => { eprintln!("AKE102: {e}"); 1 }
        },
        _ => { print_help(); 2 }
    }
}

fn audit_command(args: &[String]) -> i32 {
    if args.len() < 2 { print_help(); return 2; }
    match args[1].as_str() {
        "list" => {
            let mut limit = None;
            let mut i = 2usize;
            while i < args.len() {
                if args[i] == "--limit" && i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(v) if v <= 10000 => limit = Some(v),
                        _ => { eprintln!("AKE121: invalid audit limit"); return 2; }
                    }
                    i += 2;
                } else {
                    eprintln!("AKE121: unknown audit option");
                    return 2;
                }
            }
            match audit::show(limit) {
                Ok(events) => {
                    for event in events {
                        println!("{} {} {} pid={} package={} version={} {}", event.timestamp_ms, event.event, event.result, event.pid, event.package_id, event.version, event.details);
                    }
                    0
                }
                Err(e) => { eprintln!("AKE121: {e}"); 1 }
            }
        }
        "clear" if args.len() == 2 => match audit::clear() {
            Ok(()) => { println!("AKE audit log cleared."); 0 }
            Err(e) => { eprintln!("AKE121: {e}"); 1 }
        },
        _ => { print_help(); 2 }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return;
    }

    if args[0] != "audit" {
        let detail = args.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(" ");
        let _ = audit::log(audit::CLI_COMMAND, "requested", "", "", &detail);
    }

    match args[0].as_str() {
        "verify" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(verify(&args[1]));
        }
        "info" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(info(&args[1]));
        }
        "run" => {
            if args.len() < 2 { print_help(); std::process::exit(2); }
            if args[1] == "--detach" || args[1] == "-d" {
                if args.len() < 3 { print_help(); std::process::exit(2); }
                let target = &args[2];
                let status = if Path::new(target).extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("ake")).unwrap_or(false) {
                    detached_archive_package(target, &args[3..])
                } else {
                    detached_installed_package(target, &args[3..])
                };
                std::process::exit(status);
            }
            std::process::exit(run_package(&args[1], &args[2..]));
        }
        "ps" => {
            if args.len() > 2 || (args.len() == 2 && args[1] != "--all" && args[1] != "-a") { print_help(); std::process::exit(2); }
            std::process::exit(list_processes(args.len() == 2));
        }
        "logs" => {
            if args.len() < 2 || args.len() > 4 { print_help(); std::process::exit(2); }
            let mut tail = None;
            if args.len() == 4 {
                if args[2] != "--tail" { print_help(); std::process::exit(2); }
                tail = match args[3].parse::<usize>() { Ok(v) => Some(v), Err(_) => { eprintln!("AKE002: invalid tail count"); std::process::exit(2); } };
            }
            std::process::exit(logs_command(&args[1], tail));
        }
        "stop" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(stop_command(&args[1]));
        }
        "pack" => {
            if args.len() != 3 { print_help(); std::process::exit(2); }
            std::process::exit(pack(&args[1], &args[2]));
        }
        "extract" => {
            if args.len() != 3 { print_help(); std::process::exit(2); }
            std::process::exit(extract(&args[1], &args[2]));
        }
        "install" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(install(&args[1]));
        }
        "update" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(update_package(&args[1]));
        }
        "remove" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(remove_package(&args[1]));
        }
        "list" => {
            if args.len() != 1 { print_help(); std::process::exit(2); }
            std::process::exit(list_installed());
        }
        "which" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(which_package(&args[1]));
        }
        "search" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(search_repository(&args[1]));
        }
        "repo" => {
            std::process::exit(repository_command(&args));
        }
        "trust" => {
            std::process::exit(trust_command(&args));
        }
        "ports" => {
            if args.len() != 2 { print_help(); std::process::exit(2); }
            std::process::exit(ports_command(&args[1]));
        }
        "ipc" => {
            std::process::exit(ipc_command(&args));
        }
        "integration" => {
            std::process::exit(integration_command(&args));
        }
        "audit" => {
            std::process::exit(audit_command(&args));
        }
        "service" => {
            std::process::exit(service_command(&args));
        }
        "volume" => {
            std::process::exit(volume_command(&args));
        }
        "keygen" => {
            if args.len() != 3 { print_help(); std::process::exit(2); }
            match signing::keygen(&args[1], &args[2]) {
                Ok(()) => { println!("Generated AKE ECDSA P-256 key pair."); 0 }
                Err(e) => { eprintln!("AKE060: {e}"); 1 }
            }
        }
        "sign" => {
            if args.len() < 3 || args.len() > 4 { print_help(); std::process::exit(2); }
            match signing::sign(&args[1], &args[2], args.get(3).map(String::as_str)) {
                Ok(path) => { println!("Created signature: {}", path.display()); 0 }
                Err(e) => { eprintln!("AKE061: {e}"); 1 }
            }
        }
        "verify-signature" => {
            if args.len() < 2 || args.len() > 3 { print_help(); std::process::exit(2); }
            match signing::verify(&args[1], args.get(2).map(String::as_str)) {
                Ok(()) => { println!("Valid AKE signature: {}", args[1]); 0 }
                Err(e) => { eprintln!("AKE062: {e}"); 1 }
            }
        }
        "--version" | "-V" => println!("ake 1.0.0"),
        _ => { eprintln!("AKE001: unknown command: {}", args[0]); print_help(); std::process::exit(2); }
    }
}


#[cfg(test)]
mod dependency_tests {
    use super::*;

    #[test]
    fn dependency_parser_supports_constraints() {
        let info = "dependency=runtime>=2.1.0\ndependency=tools=3.0.0\ndependency=graphics";
        let deps = parse_dependencies(info).unwrap();
        assert_eq!(deps, vec![
            ("runtime".to_string(), ">=2.1.0".to_string()),
            ("tools".to_string(), "=3.0.0".to_string()),
            ("graphics".to_string(), "*".to_string()),
        ]);
    }

    #[test]
    fn dependency_versions_compare_semver_like() {
        assert!(compare_versions("2.0.0", "1.9.9").is_gt());
        assert!(compare_versions("2.0.0-beta", "2.0.0").is_lt());
        assert!(version_satisfies("2.1.0", ">=2.0.0"));
        assert!(version_satisfies("3.0.0", "=3.0.0"));
        assert!(!version_satisfies("1.9.0", ">=2.0.0"));
    }
}
