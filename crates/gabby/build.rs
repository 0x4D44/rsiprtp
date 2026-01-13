use std::env;

fn main() {
    if cfg!(target_os = "windows") {
        println!("cargo:rerun-if-env-changed=VOSK_LIB_DIR");

        match env::var("VOSK_LIB_DIR") {
            Ok(path) => {
                println!("cargo:rustc-link-search=native={path}");
            }
            Err(_) => {
                let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
                let script_path = format!("{manifest_dir}\\scripts\\setup_windows.ps1");

                println!("cargo:warning=VOSK_LIB_DIR is not set; Gabby requires Vosk on Windows.");
                println!(
                    "cargo:warning=Run: powershell -ExecutionPolicy Bypass -File \"{script_path}\""
                );
                println!("cargo:warning=Then re-run: cargo build -p gabby");
                println!("cargo:warning=Ensure the directory containing vosk.dll is on PATH at runtime.");
            }
        }
    } else {
        // Tell the linker to look in /usr/local/lib for libvosk
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
}
