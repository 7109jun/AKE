use std::ffi::CString;
use std::path::{Path, PathBuf};

unsafe extern "C" {
    fn ake_registry_set_classes(key: *const i8, value_name: *const i8, value_data: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_registry_query_classes(key: *const i8, value_name: *const i8, out: *mut i8, out_size: usize) -> i32;
    fn ake_registry_delete_classes(key: *const i8, value_name: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_registry_delete_tree_classes(key: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_create_shortcut(kind: *const i8, name: *const i8, target: *const i8, arguments: *const i8, working_directory: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_remove_shortcut(kind: *const i8, name: *const i8, error: *mut i8, error_size: usize) -> i32;
}

#[derive(Clone, Debug)] struct RegistrySpec { key: String, value: String, data: String }
#[derive(Clone, Debug)] struct AssocSpec { extension: String, progid: String, description: String, command: String }
#[derive(Clone, Debug)] struct ProtocolSpec { scheme: String, description: String, command: String }
#[derive(Clone, Debug)] struct ShortcutSpec { name: String, target: String, arguments: String, working_directory: String, location: String }

fn field(info: &str, key: &str) -> Option<String> { info.lines().find_map(|line| line.strip_prefix(key).map(ToOwned::to_owned)) }
fn groups(info: &str, prefix: &str) -> Vec<String> {
    let mut set=std::collections::BTreeSet::new();
    for line in info.lines() { if let Some(rest)=line.strip_prefix(prefix) { if let Some((n,_))=rest.split_once('.') { if !n.is_empty(){set.insert(n.to_string());} } } }
    set.into_iter().collect()
}
fn parse(info: &str) -> Result<(Vec<RegistrySpec>,Vec<AssocSpec>,Vec<ProtocolSpec>,Vec<ShortcutSpec>),String> {
    let id=field(info,"id=").ok_or_else(||"package id missing".to_string())?;
    let mut regs=Vec::new(); let mut assocs=Vec::new(); let mut protocols=Vec::new(); let mut shortcuts=Vec::new();
    for n in groups(info,"registry.") {
        let key=field(info,&format!("registry.{n}.key=")).unwrap_or_default(); let value=field(info,&format!("registry.{n}.value=")).unwrap_or_default(); let data=field(info,&format!("registry.{n}.data=")).unwrap_or_default();
        let expected=format!("AKE\\Packages\\{id}\\");
        if key.is_empty() || data.is_empty() || !key.starts_with(&expected) || key.contains("..") || key.contains('/') || key.contains('\0') { return Err(format!("registry.{n}: key must be under {expected}")); }
        if value.contains('\0')||data.contains('\0'){return Err(format!("registry.{n}: NUL is not allowed"));}
        regs.push(RegistrySpec{key,value,data});
    }
    for n in groups(info,"association.") {
        let extension=field(info,&format!("association.{n}.extension=")).unwrap_or_default(); let progid=field(info,&format!("association.{n}.progid=")).unwrap_or_default(); let description=field(info,&format!("association.{n}.description=")).unwrap_or_else(||progid.clone()); let command=field(info,&format!("association.{n}.command=")).unwrap_or_default();
        if !extension.starts_with('.') || extension.len()>32 || extension.contains('/')||extension.contains('\\')||extension.contains(' ') { return Err(format!("association.{n}: invalid extension")); }
        if !progid.starts_with("AKE.") || progid.contains('/')||progid.contains('\\')||progid.contains(' ') { return Err(format!("association.{n}: invalid progid")); }
        if command.is_empty(){return Err(format!("association.{n}: command is required"));}
        assocs.push(AssocSpec{extension,progid,description,command});
    }
    for n in groups(info,"protocol.") {
        let scheme=field(info,&format!("protocol.{n}.scheme=")).unwrap_or_default(); let description=field(info,&format!("protocol.{n}.description=")).unwrap_or_else(||scheme.clone()); let command=field(info,&format!("protocol.{n}.command=")).unwrap_or_default();
        if scheme.is_empty() || !scheme.chars().all(|c|c.is_ascii_alphanumeric()||c=='+'||c=='-'||c=='.') { return Err(format!("protocol.{n}: invalid scheme")); }
        if command.is_empty(){return Err(format!("protocol.{n}: command is required"));}
        protocols.push(ProtocolSpec{scheme,description,command});
    }
    for n in groups(info,"shortcut.") {
        let name=field(info,&format!("shortcut.{n}.name=")).unwrap_or_default(); let target=field(info,&format!("shortcut.{n}.target=")).unwrap_or_default(); let arguments=field(info,&format!("shortcut.{n}.arguments=")).unwrap_or_default(); let working_directory=field(info,&format!("shortcut.{n}.working-directory=")).unwrap_or_default(); let location=field(info,&format!("shortcut.{n}.location=")).unwrap_or_else(||"start-menu".to_string());
        if name.is_empty()||name.contains('/')||name.contains('\\')||name.contains('\0'){return Err(format!("shortcut.{n}: invalid name"));}
        if !target.starts_with("bin/")||!target.ends_with(".exe")||target.contains("..")||target.contains('\\'){return Err(format!("shortcut.{n}: target must be bin/*.exe"));}
        if !working_directory.is_empty() && working_directory!="." && working_directory!="bin" {return Err(format!("shortcut.{n}: working-directory must be . or bin"));}
        if location!="start-menu"&&location!="desktop"{return Err(format!("shortcut.{n}: invalid location"));}
        shortcuts.push(ShortcutSpec{name,target,arguments,working_directory,location});
    }
    Ok((regs,assocs,protocols,shortcuts))
}
fn c(s:&str)->Result<CString,String>{CString::new(s).map_err(|_|"integration value contains NUL".to_string())}
fn err(buf:&[i8])->String{unsafe{std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()}}
fn native_available(rc:i32)->bool{rc!=3}
fn reg_set(key:&str,value:&str,data:&str)->Result<(),String>{
    let k=c(key)?;let v=c(value)?;let d=c(data)?;let mut e=vec![0i8;512];let rc=unsafe{ake_registry_set_classes(k.as_ptr(),v.as_ptr(),d.as_ptr(),e.as_mut_ptr(),e.len())}; if rc==3{return Ok(());} if rc!=0{Err(err(&e))}else{Ok(())}
}
fn reg_del(key:&str,value:&str)->Result<(),String>{let k=c(key)?;let v=c(value)?;let mut e=vec![0i8;512];let rc=unsafe{ake_registry_delete_classes(k.as_ptr(),v.as_ptr(),e.as_mut_ptr(),e.len())};if rc==3||rc==2{Ok(())}else if rc!=0{Err(err(&e))}else{Ok(())}}
fn reg_tree(key:&str)->Result<(),String>{let k=c(key)?;let mut e=vec![0i8;512];let rc=unsafe{ake_registry_delete_tree_classes(k.as_ptr(),e.as_mut_ptr(),e.len())};if rc==3||rc==2{Ok(())}else if rc!=0{Err(err(&e))}else{Ok(())}}
fn reg_default(key:&str)->Result<Option<String>,String>{let k=c(key)?;let v=c("")?;let mut o=vec![0i8;2048];let rc=unsafe{ake_registry_query_classes(k.as_ptr(),v.as_ptr(),o.as_mut_ptr(),o.len())};if rc==3{return Ok(None);}if rc==2{return Ok(None);}if rc!=0{return Err(err(&o));}Ok(Some(err(&o)))}
fn abs_entry(root:&Path,entry:&str)->Result<PathBuf,String>{let rel=entry.strip_prefix("bin/").unwrap_or_default();let p=root.join("bin").join(rel).canonicalize().map_err(|e|format!("cannot resolve entry: {e}"))?;if !p.is_file(){return Err("entry executable is missing".to_string());}Ok(p)}
fn expand_command(command:&str,program:&Path)->String{command.replace("%PROGRAM%", &format!("\"{}\"",program.display()))}

pub fn install(id:&str,root:&Path,info:&str)->Result<(),String>{
    let (regs,assocs,protocols,shortcuts)=parse(info)?; if cfg!(not(windows)){let _=id;let _=root;return Ok(());} let program=abs_entry(root,&field(info,"entry=").ok_or_else(||"entry missing".to_string())?)?;
    let mut touched=Vec::<String>::new(); let mut links=Vec::<(String,String)>::new();
    let result=(||{
        for a in &assocs { if reg_default(&a.extension)?.is_some(){return Err(format!("file association {} already has a handler",a.extension));} let progkey=a.progid.clone(); let cmd=format!("{}\\shell\\open\\command",a.progid); reg_set(&a.extension,"",&a.progid)?; reg_set(&progkey,"",&a.description)?; reg_set(&cmd,"",&expand_command(&a.command,&program))?; touched.push(a.extension.clone()); touched.push(a.progid.clone()); }
        for p in &protocols { if reg_default(&p.scheme)?.is_some(){return Err(format!("protocol {} already exists",p.scheme));} reg_set(&p.scheme,"",&p.description)?; reg_set(&p.scheme,"URL Protocol","")?; reg_set(&format!("{}\\shell\\open\\command",p.scheme),"",&expand_command(&p.command,&program))?; touched.push(p.scheme.clone()); }
        for r in &regs { reg_set(&r.key,&r.value,&r.data)?; touched.push(r.key.clone()); }
        for s in &shortcuts { let target=abs_entry(root,&s.target)?; let kind=c(&s.location)?;let name=c(&s.name)?;let t=c(&target.to_string_lossy())?;let a=c(&s.arguments)?;let wd_path=if s.working_directory.is_empty()||s.working_directory=="."{root.to_path_buf()}else{root.join("bin")};let wd=c(&wd_path.to_string_lossy())?;let mut e=vec![0i8;512];let rc=unsafe{ake_create_shortcut(kind.as_ptr(),name.as_ptr(),t.as_ptr(),a.as_ptr(),wd.as_ptr(),e.as_mut_ptr(),e.len())};if rc==3{continue;}if rc!=0{return Err(err(&e));}links.push((s.location.clone(),s.name.clone())); }
        Ok(())
    })();
    if let Err(e)=result {for (k,n) in links.into_iter().rev(){if let(Ok(k),Ok(n))=(c(&k),c(&n)){let mut b=vec![0i8;256];unsafe{ake_remove_shortcut(k.as_ptr(),n.as_ptr(),b.as_mut_ptr(),b.len());}}}for k in touched.into_iter().rev(){let _=reg_tree(&k);let _=reg_del(&k,"");}return Err(e);}Ok(())
}

pub fn remove(_id:&str,info:&str)->Result<(),String>{let (regs,assocs,protocols,shortcuts)=parse(info)?;if cfg!(not(windows)){return Ok(());}for s in shortcuts.iter().rev(){let k=c(&s.location)?;let n=c(&s.name)?;let mut e=vec![0i8;256];let rc=unsafe{ake_remove_shortcut(k.as_ptr(),n.as_ptr(),e.as_mut_ptr(),e.len())};if rc!=0&&rc!=2&&rc!=3{return Err(err(&e));}}for p in protocols.iter().rev(){reg_tree(&p.scheme)?;}for a in assocs.iter().rev(){if reg_default(&a.extension)?.as_deref()==Some(&a.progid){reg_del(&a.extension,"")?;}reg_tree(&a.progid)?; }for r in regs.iter().rev(){reg_del(&r.key,&r.value)?;}Ok(())}
pub fn status(_id:&str,info:&str)->Result<Vec<String>,String>{let (r,a,p,s)=parse(info)?;Ok(vec![format!("platform={}",if cfg!(windows){"windows"}else{"unsupported-on-current-platform"}),format!("registry={}",r.len()),format!("associations={}",a.len()),format!("protocols={}",p.len()),format!("shortcuts={}",s.len())])}

#[cfg(test)]
mod tests {use super::*;#[test]fn parse_windows_metadata(){let i="id=com.example.app\nentry=bin/app.exe\nregistry.base.key=AKE\\Packages\\com.example.app\\Settings\nregistry.base.value=Mode\nregistry.base.data=portable\nassociation.one.extension=.foo\nassociation.one.progid=AKE.Foo\nassociation.one.description=Foo\nassociation.one.command=%PROGRAM% %1\nprotocol.web.scheme=foo\nprotocol.web.description=Foo Protocol\nprotocol.web.command=%PROGRAM% %1\nshortcut.main.name=Foo\nshortcut.main.target=bin/app.exe\nshortcut.main.location=start-menu\n";let (r,a,p,s)=parse(i).unwrap();assert_eq!(r.len(),1);assert_eq!(a.len(),1);assert_eq!(p.len(),1);assert_eq!(s.len(),1);}}
