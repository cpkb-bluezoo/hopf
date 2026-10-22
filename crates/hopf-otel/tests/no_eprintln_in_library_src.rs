// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Guard against direct stderr logging outside hopf-otel diagnostics.

use std::path::{Path, PathBuf};

#[test]
fn library_crates_do_not_use_eprintln_macro() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let crates_dir = workspace.join("crates");
    for entry in std::fs::read_dir(&crates_dir).expect("crates dir") {
        let entry = entry.expect("crate dir entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let src = entry.path().join("src");
        if !src.is_dir() {
            continue;
        }
        walk_rs(&src, &mut |path, contents| {
            if path.starts_with(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            ) {
                return;
            }
            assert!(
                !contents.contains("eprintln!"),
                "{} must not use eprintln! (route through TelemetryHook / hopf_core::subsystem_log)",
                path.display()
            );
        });
    }
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let contents = std::fs::read_to_string(&path).expect("read rs");
            f(&path, &contents);
        }
    }
}
