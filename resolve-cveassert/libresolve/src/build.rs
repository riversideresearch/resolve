fn main() {
    println!("cargo:warning=LINKING_MIMALLOC_ARCHIVE");
    // TODO: Fill in this with the correct path
    println!("cargo:rustc-link-search=native=/mimalloc/build");
    println!("cargo:rustc-link-lib=static=mimalloc");
}
