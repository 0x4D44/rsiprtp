//! Inventory check: every fuzz target file is referenced by at least one
//! wrapper script. Prevents drift where a target is added to the repo but
//! nobody schedules it into a campaign.
//!
//! Sister-direction (every wrapper-named target exists as a file) is not
//! enforced here — cargo-fuzz fails loudly at run time on a missing target,
//! so the value of catching that at test time is low.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR -> crates/rsiprtp; up two levels -> repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("repo root from CARGO_MANIFEST_DIR")
}

fn list_target_names(dir: &Path) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension().and_then(|s| s.to_str()) == Some("rs"))
                .then(|| p.file_stem().and_then(|s| s.to_str()).map(String::from))
                .flatten()
        })
        .collect()
}

fn collect_wrappers(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    // Repo-root wrappers: any *.ps1 with "fuzz" in the filename. After the
    // followup-C consolidation (single root fuzz/ crate), this is the only
    // location where wrapper scripts live.
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("ps1")
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.contains("fuzz"))
            {
                out.push(p);
            }
        }
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Word-boundary substring match. Avoids `sip_via` falsely matching inside
/// `sip_via_typed` (which would let a wrapper that schedules the typed
/// variant satisfy the inventory check for the legacy one too).
fn references_target(content: &str, target: &str) -> bool {
    let bytes = content.as_bytes();
    let needle = target.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    for i in 0..=bytes.len() - needle.len() {
        if &bytes[i..i + needle.len()] != needle {
            continue;
        }
        let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
        let after_ok = i + needle.len() == bytes.len() || !is_ident_byte(bytes[i + needle.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

#[test]
fn every_fuzz_target_is_scheduled_in_some_wrapper() {
    let root = repo_root();

    let mut targets: BTreeSet<String> = BTreeSet::new();
    targets.extend(list_target_names(&root.join("fuzz").join("fuzz_targets")));
    assert!(
        !targets.is_empty(),
        "no fuzz targets found under {}/fuzz/fuzz_targets",
        root.display()
    );

    let wrappers = collect_wrappers(&root);
    assert!(
        !wrappers.is_empty(),
        "no fuzz wrapper .ps1 files found at {}",
        root.display()
    );

    let wrapper_contents: Vec<(PathBuf, String)> = wrappers
        .iter()
        .map(|p| {
            (
                p.clone(),
                fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())),
            )
        })
        .collect();

    let unwired: Vec<&String> = targets
        .iter()
        .filter(|t| {
            !wrapper_contents
                .iter()
                .any(|(_, c)| references_target(c, t))
        })
        .collect();

    if !unwired.is_empty() {
        let wrappers_list = wrapper_contents
            .iter()
            .map(|(p, _)| format!("    - {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n");
        let unwired_list = unwired
            .iter()
            .map(|t| format!("    - {}", t))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "{} fuzz target(s) not referenced by any wrapper:\n{}\n\nWrappers scanned:\n{}\n\n\
             Either schedule each target in a wrapper, or delete the target file.",
            unwired.len(),
            unwired_list,
            wrappers_list
        );
    }
}
