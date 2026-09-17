
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::env;

unsafe extern "C" {
    fn ake_service_install(name:*const i8,display_name:*const i8,description:*const i8,binary_path:*const i8,start_mode:i32,account_mode:i32,restart_mode:i32,restart_retries:u32,restart_delay_ms:u32,restart_backoff:u32,restart_reset_sec:u32,error:*mut i8,error_size:usize)->i32;
    fn ake_service_delete(name:*const i8,error:*mut i8,error_size:usize)->i32;
    fn ake_service_start(name:*const i8,error:*mut i8,error_size:usize)->i32;
    fn ake_service_stop(name:*const i8,error:*mut i8,error_size:usize)->i32;
    fn ake_service_query(name:*const i8,state:*mut i8,state_size:usize,pid:*mut u32,error:*mut i8,error_size:usize)->i32;
    fn ake_service_host(service_name:*const i8,program:*const i8,arguments:*const i8,working_directory:*const i8,environment_block_utf8:*const u8,environment_size:usize,container_name:*const i8,filesystem_mode:i32,process_mode:i32,network_mode:i32,identity_mode:i32,memory_limit_bytes:u64,cpu_rate_percent_x100:u32,active_process_limit:u32,process_user_time_100ns:u64,job_name:*const i8,restart_mode:i32)->i32;
}

#[derive(Clone,Debug)]
struct ServiceSpec { name:String, display_name:String, description:String, start:i32, account:i32, restart:i32, restart_retries:u32, restart_delay_ms:u32, restart_backoff:u32, restart_reset_sec:u32 }

fn field(info:&str,key:&str)->Option<String>{info.lines().find_map(|line|line.strip_prefix(key).and_then(|x|x.strip_prefix('=')).map(str::to_string))}
fn has(info:&str,prefix:&str)->bool{info.lines().any(|l|l.starts_with(prefix))}
fn valid_name(s:&str)->bool{!s.is_empty()&&s.len()<=80&&s.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-'|b'.'))}
fn default_name(id:&str)->String{let mut x=String::from("AKE.");for c in id.chars(){if c.is_ascii_alphanumeric()||matches!(c,'_'|'-'|'.'){x.push(c)}else{x.push('_');}}x.truncate(80);x}
fn parse(info:&str,id:&str)->Result<Option<ServiceSpec>,String>{
    if !has(info,"service."){return Ok(None);}
    let name=field(info,"service.name").unwrap_or_else(||default_name(id));
    if !valid_name(&name){return Err("service.name is invalid".into());}
    let display=field(info,"service.display-name").unwrap_or_else(||name.clone());
    if display.is_empty()||display.len()>256||display.contains('\0'){return Err("service.display-name is invalid".into());}
    let description=field(info,"service.description").unwrap_or_default();
    if description.len()>1024||description.contains('\0'){return Err("service.description is invalid".into());}
    let start=match field(info,"service.start").unwrap_or_else(||"manual".into()).as_str(){"auto"=>0,"manual"|"demand"=>1,"disabled"=>2,other=>return Err(format!("invalid service.start: {other}"))};
    let account=match field(info,"service.account").unwrap_or_else(||"localservice".into()).to_ascii_lowercase().as_str(){"localservice"=>0,"networkservice"=>1,"localsystem"=>2,other=>return Err(format!("invalid service.account: {other}"))};
    let restart=match field(info,"service.restart").unwrap_or_else(||"never".into()).to_ascii_lowercase().as_str(){
        "never"=>0,"on-failure"|"on_failure"=>1,"always"=>2,other=>return Err(format!("invalid service.restart: {other}"))
    };
    let restart_retries=parse_u32_range(info,"service.restart.max-retries",if restart==0{0}else{5},0,32)?;
    let restart_delay_ms=parse_duration_ms(info,"service.restart.delay",5000,100,86_400_000)?;
    let restart_backoff=parse_u32_range(info,"service.restart.backoff",2,1,10)?;
    let restart_reset_sec=parse_u32_range(info,"service.restart.reset",86400,0,31_536_000)?;
    if restart==0 && restart_retries!=5 && field(info,"service.restart.max-retries").is_some(){
        // Keep explicit never semantics unambiguous: retry count is ignored, but invalid values were still rejected.
    }
    Ok(Some(ServiceSpec{name,display_name:display,description,start,account,restart,restart_retries,restart_delay_ms,restart_backoff,restart_reset_sec}))
}
fn parse_u32_range(info:&str,key:&str,default:u32,min:u32,max:u32)->Result<u32,String>{
    let Some(raw)=field(info,key) else { return Ok(default); };
    let v=raw.parse::<u32>().map_err(|_|format!("{key} must be an unsigned integer"))?;
    if v<min || v>max { return Err(format!("{key} out of range ({min}..={max})")); }
    Ok(v)
}
fn parse_duration_ms(info:&str,key:&str,default_ms:u32,min_ms:u32,max_ms:u32)->Result<u32,String>{
    let Some(raw)=field(info,key) else { return Ok(default_ms); };
    let (num,suffix)=if let Some(v)=raw.strip_suffix("ms"){(v,"ms")}else if let Some(v)=raw.strip_suffix('s'){(v,"s")}else if let Some(v)=raw.strip_suffix('m'){(v,"m")}else if let Some(v)=raw.strip_suffix('h'){(v,"h")}else{(raw.as_str(),"ms")};
    let base=num.parse::<u64>().map_err(|_|format!("{key} has invalid duration: {raw}"))?;
    let ms=match suffix {"ms"=>base,"s"=>base.saturating_mul(1000),"m"=>base.saturating_mul(60_000),"h"=>base.saturating_mul(3_600_000),_=>return Err(format!("{key} has invalid duration"))};
    if ms<min_ms as u64 || ms>max_ms as u64 || ms>u32::MAX as u64 { return Err(format!("{key} out of range")); }
    Ok(ms as u32)
}
fn c(s:&str)->Result<CString,String>{CString::new(s).map_err(|_|"service value contains NUL".into())}
fn err(b:&[i8])->String{unsafe{std::ffi::CStr::from_ptr(b.as_ptr()).to_string_lossy().into_owned()}}
fn service_binary_path(id:&str)->Result<String,String>{let exe=env::current_exe().map_err(|e|format!("cannot locate ake.exe: {e}"))?;Ok(format!("{} service host {}",crate::quote_windows_arg(&exe.to_string_lossy()),crate::quote_windows_arg(id)))}
fn spec(info:&str,id:&str)->Result<ServiceSpec,String>{parse(info,id)?.ok_or_else(||"package does not declare a Windows service".into())}
pub fn validate(info:&str,id:&str)->Result<(),String>{let _=parse(info,id)?;Ok(())}

pub fn install(id:&str,_root:&Path,info:&str)->Result<(),String>{
    let s=match parse(info,id)?{Some(v)=>v,None=>return Ok(())};
    if !cfg!(windows){return Ok(());}
    let name=c(&s.name)?;let display=c(&s.display_name)?;let description=c(&s.description)?;let binary=c(&service_binary_path(id)?)?;let mut e=vec![0i8;512];let rc=unsafe{ake_service_install(name.as_ptr(),display.as_ptr(),description.as_ptr(),binary.as_ptr(),s.start,s.account,s.restart,s.restart_retries,s.restart_delay_ms,s.restart_backoff,s.restart_reset_sec,e.as_mut_ptr(),e.len())};if rc!=0{Err({let m=err(&e);if m.is_empty(){format!("Windows service API failed with code {rc}")}else{m}})}else{Ok(())}
}
pub fn remove(id:&str,info:&str)->Result<(),String>{let s=match parse(info,id)?{Some(v)=>v,None=>return Ok(())};if !cfg!(windows){return Ok(());}let n=c(&s.name)?;let mut e=vec![0i8;512];let rc=unsafe{ake_service_delete(n.as_ptr(),e.as_mut_ptr(),e.len())};if rc!=0{Err(err(&e))}else{Ok(())}}
pub fn start(id:&str,info:&str)->Result<(),String>{let s=spec(info,id)?;if !cfg!(windows){return Err("Windows services require a Windows build".into());}let n=c(&s.name)?;let mut e=vec![0i8;512];let rc=unsafe{ake_service_start(n.as_ptr(),e.as_mut_ptr(),e.len())};if rc!=0{Err(err(&e))}else{Ok(())}}
pub fn stop(id:&str,info:&str)->Result<(),String>{let s=spec(info,id)?;if !cfg!(windows){return Err("Windows services require a Windows build".into());}let n=c(&s.name)?;let mut e=vec![0i8;512];let rc=unsafe{ake_service_stop(n.as_ptr(),e.as_mut_ptr(),e.len())};if rc!=0{Err(err(&e))}else{Ok(())}}
pub fn status(id:&str,info:&str)->Result<String,String>{let s=spec(info,id)?;if !cfg!(windows){return Ok("platform=unsupported-on-current-platform".into());}let n=c(&s.name)?;let mut state=vec![0i8;64];let mut pid=0u32;let mut e=vec![0i8;512];let rc=unsafe{ake_service_query(n.as_ptr(),state.as_mut_ptr(),state.len(),&mut pid,e.as_mut_ptr(),e.len())};if rc!=0&&rc!=2{return Err(err(&e));}let st=if rc==2{"not-installed"}else{err(&state)};Ok(format!("name={}\nstate={}\npid={}\nstart={}\naccount={}\nrestart={}\nrestart-max-retries={}\nrestart-delay-ms={}\nrestart-backoff={}\nrestart-reset-sec={}",s.name,st,pid,match s.start{0=>"auto",1=>"manual",2=>"disabled",_=>"unknown"},match s.account{0=>"localservice",1=>"networkservice",2=>"localsystem",_=>"unknown"},match s.restart{0=>"never",1=>"on-failure",2=>"always",_=>"unknown"},s.restart_retries,s.restart_delay_ms,s.restart_backoff,s.restart_reset_sec))}

pub fn host(id:&str)->i32{
    if !cfg!(windows){eprintln!("AKE027: Windows service host requires a Windows build");return 1;}
    let pkg=match crate::package_db::find(id){Ok(v)=>v,Err(e)=>{eprintln!("AKE027: {e}");return 1;}};
    let info=match crate::read_installed_info(&pkg){Ok(v)=>v,Err(e)=>{eprintln!("AKE027: {e}");return 1;}};
    let s=match spec(&info,id){Ok(v)=>v,Err(e)=>{eprintln!("AKE027: {e}");return 1;}};
    let entry=match crate::metadata_field(&info,"entry"){Some(v)=>v,None=>{eprintln!("AKE010: package entry is missing");return 1;}};
    if !entry.starts_with("bin/")||entry.contains("..")||entry.contains('\\'){eprintln!("AKE010: package entry is invalid");return 1;}
    let root=match pkg.install_dir.canonicalize(){Ok(v)=>v,Err(e)=>{eprintln!("AKE027: cannot resolve package root: {e}");return 1;}};
    let program=root.join(&entry);if !program.is_file(){eprintln!("AKE027: service entry executable is missing");return 1;}
    let specs=match crate::volume::parse_specs(&info){Ok(v)=>v,Err(e)=>{eprintln!("AKE018: {e}");return 1;}};
    if let Err(e)=crate::volume::mount_all(&specs,&root){eprintln!("AKE018: {e}");return 1;}
    let result=(||{
        let (policy,resources,container_name,_pid,fs_mode,proc_mode,net_mode,id_mode)=match crate::launch_parameters(&info){Ok(v)=>v,Err(e)=>return Err(e)};
        let env=crate::build_child_environment(&info,&root,&specs)?;
        let p=c(&s.name)?;let prog=c(&program.to_string_lossy())?;let args=c("")?;let cwd=c(&root.to_string_lossy())?;let cname=c(&container_name)?;
        let job_name=format!("AKE_SERVICE_{}",crate::runtime_state::new_id());let job=c(&job_name)?;
        let log_dir=crate::package_db::root().join("runtime").join("services");std::fs::create_dir_all(&log_dir).map_err(|e|format!("cannot create service log directory: {e}"))?;let log=log_dir.join(format!("{}.log",s.name));
        let _log_s=c(&log.to_string_lossy())?;let _=policy;
        let rc=unsafe{ake_service_host(p.as_ptr(),prog.as_ptr(),args.as_ptr(),cwd.as_ptr(),env.as_ptr(),env.len(),cname.as_ptr(),fs_mode,proc_mode,net_mode,id_mode,resources.memory_bytes,resources.cpu_rate_percent_x100,resources.active_processes,resources.process_user_time_100ns,job.as_ptr(),s.restart)};
        if rc!=0{Err(format!("Windows service host failed with code {rc}"))}else{Ok(())}
    })();
    let _=crate::volume::unmount_all(&specs,&root);
    match result{Ok(())=>0,Err(e)=>{eprintln!("AKE027: {e}");1}}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn parse_service(){let x="service.name=AKE.Example\nservice.display-name=Example\nservice.description=Example service\nservice.start=auto\nservice.account=localservice\nservice.restart=on-failure\nservice.restart.max-retries=7\nservice.restart.delay=2s\nservice.restart.backoff=3\nservice.restart.reset=1h\n";let s=parse(x,"com.example.example").unwrap().unwrap();assert_eq!(s.start,0);assert_eq!(s.account,0);assert_eq!(s.name,"AKE.Example");assert_eq!(s.restart,1);assert_eq!(s.restart_retries,7);assert_eq!(s.restart_delay_ms,2000);assert_eq!(s.restart_backoff,3);assert_eq!(s.restart_reset_sec,3600);}
    #[test]fn no_service_is_ok(){assert!(parse("id=a\n","com.example.a").unwrap().is_none());}
    #[test]fn default_name_is_safe(){let s=parse("service.description=x\n","com.example.test").unwrap().unwrap();assert!(valid_name(&s.name));}
    #[test]fn invalid_restart_is_rejected(){assert!(parse("service.restart=wat\n","com.example.test").is_err());assert!(parse("service.restart.delay=1ms\n","com.example.test").is_err());assert!(parse("service.restart.backoff=0\n","com.example.test").is_err());}
}
