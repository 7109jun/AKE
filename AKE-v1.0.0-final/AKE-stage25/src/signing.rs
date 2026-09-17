use std::ffi::{CStr, CString};
use std::fs;
use std::path::{Path, PathBuf};

unsafe extern "C" {
    fn ake_crypto_generate_keypair(private_path: *const i8, public_path: *const i8, error: *mut i8, error_size: usize) -> i32;
    fn ake_crypto_sign_digest(private_path: *const i8, digest: *const u8, signature: *mut u8, signature_capacity: usize, signature_size: *mut usize, error: *mut i8, error_size: usize) -> i32;
    fn ake_crypto_verify_digest(public_blob: *const u8, public_blob_size: usize, digest: *const u8, signature: *const u8, signature_size: usize, error: *mut i8, error_size: usize) -> i32;
}

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data { s.push_str(&format!("{b:02x}")); }
    s
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("hex value has odd length".into()); }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    fn nibble(c: u8) -> Option<u8> {
        match c { b'0'..=b'9' => Some(c-b'0'), b'a'..=b'f' => Some(c-b'a'+10), b'A'..=b'F' => Some(c-b'A'+10), _ => None }
    }
    for i in (0..bytes.len()).step_by(2) {
        let hi = nibble(bytes[i]).ok_or_else(|| "invalid hex".to_string())?;
        let lo = nibble(bytes[i+1]).ok_or_else(|| "invalid hex".to_string())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((data.len()+2)/3)*4);
    let mut i = 0;
    while i < data.len() {
        let a = data[i];
        let b = if i + 1 < data.len() { data[i+1] } else { 0 };
        let c = if i + 2 < data.len() { data[i+2] } else { 0 };
        out.push(T[(a >> 2) as usize] as char);
        out.push(T[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if i + 1 < data.len() { T[(((b & 15) << 2) | (c >> 6)) as usize] as char } else { '=' });
        out.push(if i + 2 < data.len() { T[(c & 63) as usize] as char } else { '=' });
        i += 3;
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || clean.len() % 4 != 0 { return Err("invalid base64 length".into()); }
    fn val(c: u8) -> Option<u8> {
        match c { b'A'..=b'Z'=>Some(c-b'A'), b'a'..=b'z'=>Some(c-b'a'+26), b'0'..=b'9'=>Some(c-b'0'+52), b'+'=>Some(62), b'/'=>Some(63), _=>None }
    }
    let mut out = Vec::with_capacity(clean.len()/4*3);
    for chunk in clean.chunks_exact(4) {
        let a = val(chunk[0]).ok_or_else(|| "invalid base64".to_string())?;
        let b = val(chunk[1]).ok_or_else(|| "invalid base64".to_string())?;
        let c = if chunk[2] == b'=' { 0 } else { val(chunk[2]).ok_or_else(|| "invalid base64".to_string())? };
        let d = if chunk[3] == b'=' { 0 } else { val(chunk[3]).ok_or_else(|| "invalid base64".to_string())? };
        if chunk[2] == b'=' && chunk[3] != b'=' { return Err("invalid base64 padding".into()); }
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' { out.push((b << 4) | (c >> 2)); }
        if chunk[3] != b'=' { out.push((c << 6) | d); }
    }
    Ok(out)
}

fn sha256(data: &[u8]) -> [u8;32] {
    const K:[u32;64]=[
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,
        0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,
        0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,
        0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,
        0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,
        0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
        0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,
        0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    fn r(x:u32,n:u32)->u32{(x>>n)|(x<<(32-n))}
    let mut h=[0x6a09e667u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut m=Vec::with_capacity(((data.len()+9+63)/64)*64); m.extend_from_slice(data); m.push(0x80); while (m.len()+8)%64!=0{m.push(0);} m.extend_from_slice(&(data.len() as u64*8).to_be_bytes());
    for ch in m.chunks_exact(64){
        let mut w=[0u32;64]; for i in 0..16{w[i]=u32::from_be_bytes([ch[i*4],ch[i*4+1],ch[i*4+2],ch[i*4+3]]);} for i in 16..64{let s0=r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>3);let s1=r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);}
        let(mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut x)=(h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64{let s1=r(e,6)^r(e,11)^r(e,25);let ch=(e&f)^((!e)&g);let t1=x.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);let s0=r(a,2)^r(a,13)^r(a,22);let maj=(a&b)^(a&c)^(b&c);let t2=s0.wrapping_add(maj);x=g;g=f;f=e;e=d.wrapping_add(t1);d=c;c=b;b=a;a=t1.wrapping_add(t2);}
        h[0]=h[0].wrapping_add(a);h[1]=h[1].wrapping_add(b);h[2]=h[2].wrapping_add(c);h[3]=h[3].wrapping_add(d);h[4]=h[4].wrapping_add(e);h[5]=h[5].wrapping_add(f);h[6]=h[6].wrapping_add(g);h[7]=h[7].wrapping_add(x);
    }
    let mut out=[0u8;32]; for i in 0..8{out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes());} out
}

fn c_error(buf: &[i8]) -> String { unsafe { CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned() } }
fn path_c(path: &Path) -> Result<CString,String> { CString::new(path.to_string_lossy().as_bytes()).map_err(|_| "path contains NUL".into()) }
fn sig_path_for(package: &Path) -> PathBuf { let mut s=package.as_os_str().to_owned(); s.push(".sig"); PathBuf::from(s) }


#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub algorithm: String,
    pub key_id: String,
    pub package_hash: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub digest: [u8; 32],
}

pub fn key_id_for_public_key(public_key: &[u8]) -> String {
    hex(&sha256(public_key))
}

pub fn read_signature(package: &Path, sig_path: &Path) -> Result<ParsedSignature, String> {
    let bytes=fs::read(package).map_err(|e|format!("cannot read package: {e}"))?;
    let digest=sha256(&bytes);
    let text=fs::read_to_string(sig_path).map_err(|e|format!("cannot read signature {}: {e}",sig_path.display()))?;
    let mut alg=None; let mut key_id=None; let mut package_hash=None; let mut pub_key=None; let mut sig=None;
    for line in text.lines(){
        if let Some(v)=line.strip_prefix("algorithm="){alg=Some(v.to_string())}
        else if let Some(v)=line.strip_prefix("key-id="){key_id=Some(v.to_string())}
        else if let Some(v)=line.strip_prefix("package-sha256="){package_hash=Some(v.to_string())}
        else if let Some(v)=line.strip_prefix("public-key="){pub_key=Some(v.to_string())}
        else if let Some(v)=line.strip_prefix("signature="){sig=Some(v.to_string())}
    }
    if !text.lines().next().is_some_and(|x|x=="AKE-SIG 1") {return Err("invalid signature format".into())}
    let algorithm=alg.ok_or("missing algorithm")?;
    if algorithm!="ECDSA-P256-SHA256"{return Err("unsupported signature algorithm".into())}
    let key_id=key_id.ok_or("missing key-id")?;
    if key_id.len()!=64 || !key_id.bytes().all(|b|b.is_ascii_hexdigit()){return Err("invalid key-id".into())}
    let package_hash=package_hash.ok_or("missing package-sha256")?;
    if package_hash.len()!=64 || !package_hash.bytes().all(|b|b.is_ascii_hexdigit()){return Err("invalid package-sha256".into())}
    let pub_key=base64_decode(&pub_key.ok_or("missing public-key")?)?;
    let signature=base64_decode(&sig.ok_or("missing signature")?)?;
    if pub_key.len()>1024*1024 || signature.len()>4096{return Err("signature payload too large".into())}
    let expected_hash=hex(&digest);
    if !package_hash.eq_ignore_ascii_case(&expected_hash){return Err("package SHA-256 does not match signature".into())}
    let actual_key_id=key_id_for_public_key(&pub_key);
    if !key_id.eq_ignore_ascii_case(&actual_key_id){return Err("public key ID mismatch".into())}
    Ok(ParsedSignature{algorithm,key_id:key_id.to_ascii_lowercase(),package_hash:package_hash.to_ascii_lowercase(),public_key:pub_key,signature,digest})
}

pub fn verify_digest_with_public_key(package: &Path, parsed: &ParsedSignature, public_key: &[u8]) -> Result<(), String> {
    let bytes=fs::read(package).map_err(|e|format!("cannot read package: {e}"))?;
    let digest=sha256(&bytes);
    if digest != parsed.digest { return Err("package changed while verifying signature".into()); }
    if public_key != parsed.public_key { return Err("verification public key mismatch".into()); }
    let mut err=vec![0i8;1024];
    let rc=unsafe{ake_crypto_verify_digest(public_key.as_ptr(),public_key.len(),digest.as_ptr(),parsed.signature.as_ptr(),parsed.signature.len(),err.as_mut_ptr(),err.len())};
    if rc!=0{return Err(if c_error(&err).is_empty(){format!("signature verification failed ({rc})")}else{c_error(&err)})}
    Ok(())
}

pub fn keygen(private_path:&str, public_path:&str)->Result<(),String>{
    let a=path_c(Path::new(private_path))?; let b=path_c(Path::new(public_path))?; let mut e=vec![0i8;1024]; let rc=unsafe{ake_crypto_generate_keypair(a.as_ptr(),b.as_ptr(),e.as_mut_ptr(),e.len())}; if rc!=0{return Err(if c_error(&e).is_empty(){format!("key generation failed ({rc})")}else{c_error(&e)})}; Ok(())
}

pub fn sign(package:&str, private_key:&str, output:Option<&str>)->Result<PathBuf,String>{
    let package_path=Path::new(package); let bytes=fs::read(package_path).map_err(|e|format!("cannot read package: {e}"))?;
    let digest=sha256(&bytes); let priv_c=path_c(Path::new(private_key))?; let mut sig=[0u8;4096]; let mut sig_len=0usize; let mut err=vec![0i8;1024];
    let rc=unsafe{ake_crypto_sign_digest(priv_c.as_ptr(),digest.as_ptr(),sig.as_mut_ptr(),sig.len(),&mut sig_len,err.as_mut_ptr(),err.len())}; if rc!=0{return Err(if c_error(&err).is_empty(){format!("signing failed ({rc})")}else{c_error(&err)})};
    let sigout=PathBuf::from(output.map(PathBuf::from).unwrap_or_else(||sig_path_for(package_path)));
    let public_guess = if Path::new(private_key).extension().and_then(|x|x.to_str()) == Some("akekey") { PathBuf::from(private_key.trim_end_matches(".akekey").to_owned()+".akepub") } else { PathBuf::from(format!("{private_key}.pub")) };
    let pub_bytes=fs::read(&public_guess).map_err(|_| format!("public key file not found; expected {}",public_guess.display()))?;
    let key_id=sha256(&pub_bytes);
    let text=format!("AKE-SIG 1\nalgorithm=ECDSA-P256-SHA256\nkey-id={}\npackage-sha256={}\npublic-key={}\nsignature={}\n",hex(&key_id),hex(&digest),base64_encode(&pub_bytes),base64_encode(&sig[..sig_len]));
    let tmp=sigout.with_extension(format!("sig.new.{}",std::process::id())); fs::write(&tmp,text.as_bytes()).map_err(|e|format!("cannot write signature: {e}"))?; fs::rename(&tmp,&sigout).map_err(|e|{let _=fs::remove_file(&tmp);format!("cannot commit signature: {e}")})?;
    Ok(sigout)
}

pub fn verify(package:&str, signature:Option<&str>)->Result<(),String>{
    let package_path=Path::new(package);
    let sig_path=PathBuf::from(signature.map(PathBuf::from).unwrap_or_else(||sig_path_for(package_path)));
    let parsed=read_signature(package_path,&sig_path)?;
    verify_digest_with_public_key(package_path,&parsed,&parsed.public_key)
}
