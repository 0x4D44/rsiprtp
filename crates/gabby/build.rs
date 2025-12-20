fn main() {
    // Tell the linker to look in /usr/local/lib for libvosk
    println!("cargo:rustc-link-search=native=/usr/local/lib");
}
