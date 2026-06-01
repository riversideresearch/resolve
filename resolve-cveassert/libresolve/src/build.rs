fn main() {
    let dir = std::env::var("MIMALLOC_LIB_DIR").unwrap();
    println!("cargo::warning=LINKING_MIMALLOC_ARCHIVE");
    println!("cargo::rustc-link-search=native={}", dir);
    println!("cargo::rustc-link-lib=static=mimalloc");
}
