fn main() {
    println!("cargo:rerun-if-changed=native/ake_core.c");
    println!("cargo:rerun-if-changed=native/ake_core.h");
    println!("cargo:rerun-if-changed=native/ake_windows.cpp");
    println!("cargo:rerun-if-changed=native/ake_windows.h");
    println!("cargo:rerun-if-changed=src/windows_integration.rs");
    println!("cargo:rerun-if-changed=src/service.rs");
    println!("cargo:rerun-if-changed=native/ake_service.cpp");
    println!("cargo:rerun-if-changed=native/ake_service.h");
    println!("cargo:rerun-if-changed=native/ake_isolation.cpp");
    println!("cargo:rerun-if-changed=native/ake_isolation.h");
    println!("cargo:rerun-if-changed=src/isolation.rs");
    println!("cargo:rerun-if-changed=src/runtime_state.rs");
    println!("cargo:rerun-if-changed=native/ake_runtime.h");
    println!("cargo:rerun-if-changed=native/ake_crypto.cpp");
    println!("cargo:rerun-if-changed=native/ake_crypto.h");
    println!("cargo:rerun-if-changed=native/ake_volume.cpp");
    println!("cargo:rerun-if-changed=native/ake_volume.h");
    println!("cargo:rerun-if-changed=native/ake_ipc.cpp");
    println!("cargo:rerun-if-changed=native/ake_ipc.h");
    println!("cargo:rerun-if-changed=src/ipc.rs");
    println!("cargo:rerun-if-changed=src/signing.rs");
    println!("cargo:rerun-if-changed=native/ake_pack.c");
    println!("cargo:rerun-if-changed=src/repository.rs");
    println!("cargo:rerun-if-changed=src/audit.rs");
    println!("cargo:rerun-if-changed=native/ake_pack.h");
    println!("cargo:rerun-if-changed=native/ake_extract.c");
    println!("cargo:rerun-if-changed=native/ake_extract.h");
    println!("cargo:rustc-link-lib=lzma");
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows") {
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=userenv");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=ole32");
    }

    cc::Build::new()
        .file("native/ake_core.c")
        .file("native/ake_pack.c")
        .file("native/ake_extract.c")
        .include("native")
        .flag_if_supported("-std=c11")
        .compile("ake_core");

    let mut cpp = cc::Build::new();
    cpp.cpp(true)
        .file("native/ake_windows.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    cpp.compile("ake_windows");

    let mut isolation = cc::Build::new();
    isolation.cpp(true)
        .file("native/ake_isolation.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    isolation.compile("ake_isolation");

    let mut crypto = cc::Build::new();
    crypto.cpp(true)
        .file("native/ake_crypto.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    crypto.compile("ake_crypto");

    let mut volume = cc::Build::new();
    volume.cpp(true)
        .file("native/ake_volume.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    volume.compile("ake_volume");

    let mut service = cc::Build::new();
    service.cpp(true)
        .file("native/ake_service.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    service.compile("ake_service");

    let mut ipc = cc::Build::new();
    ipc.cpp(true)
        .file("native/ake_ipc.cpp")
        .include("native")
        .flag_if_supported("-std=c++17");
    ipc.compile("ake_ipc");
    if std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
    }
}
