//! Command-line shape: a bad command line exits with code 64.

use std::process::Command;

fn zkar(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zkar"))
        .args(args)
        .output()
        .expect("zkar must start")
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zkar-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// An argument that is not valid UTF-8 is a bad command line. The CLI must
/// report it with exit code 64 and must not panic.
#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_a_usage_error() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let invalid_path = OsString::from_vec(vec![b'r', 0xff]);
    let output = Command::new(env!("CARGO_BIN_EXE_zkar"))
        .arg("check")
        .arg(invalid_path)
        .output()
        .expect("zkar must start");

    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("valid UTF-8"), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
}

#[test]
fn digest_without_a_file_is_a_usage_error() {
    assert_eq!(zkar(&["digest"]).status.code(), Some(64));
}

#[test]
fn digest_with_an_extra_argument_is_a_usage_error() {
    let dir = scratch_dir("digest-extra");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("input.txt");
    std::fs::write(&file, b"abc").unwrap();

    let output = zkar(&["digest", file.to_str().unwrap(), "extra"]);
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty(), "no digest may be printed");

    // The same file alone still works.
    let output = zkar(&["digest", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn fixtures_without_a_directory_is_a_usage_error() {
    assert_eq!(zkar(&["fixtures"]).status.code(), Some(64));
}

#[test]
fn fixtures_with_an_extra_argument_is_a_usage_error_and_writes_nothing() {
    let dir = scratch_dir("fixtures-extra");

    let output = zkar(&["fixtures", dir.to_str().unwrap(), "extra"]);
    assert_eq!(output.status.code(), Some(64));
    assert!(!dir.exists(), "a bad command line must not write fixtures");
}
