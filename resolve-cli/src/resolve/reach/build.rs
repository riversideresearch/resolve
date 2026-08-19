use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=RESOLVE_LIBREACH_DIR");

    let library_dir = PathBuf::from(
        env::var_os("RESOLVE_LIBREACH_DIR").expect(
            "RESOLVE_LIBREACH_DIR is not set; build through the CMake reach-rs target or set it to the native library directory",
        ),
    );

    for library in ["libreach.a", "libresolve_facts.a"] {
        let path = library_dir.join(library);
        if !path.is_file() {
            panic!("required native library does not exist: {}", path.display());
        }
    }

    println!(
        "cargo:rerun-if-changed={}",
        library_dir.join("libreach.a").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        library_dir.join("libresolve_facts.a").display()
    );
    println!("cargo:rustc-link-search=native={}", library_dir.display());
    println!("cargo:rustc-link-lib=static=reach");
    println!("cargo:rustc-link-lib=static=resolve_facts");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");
}
