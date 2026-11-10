//! Runs the sealed-receipt wire-format conformance vectors.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use zkar_core::{statement::SealedReceipt, ZkarError};

#[derive(Debug, Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    result: String,
    reason: String,
    error: Option<String>,
    member: Option<String>,
    container: Option<String>,
}

#[test]
fn receipt_files_match_the_manifest() {
    let root = vectors_path();
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(root.join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(manifest.cases.len() >= 10);

    // Every receipt file in the folder must have a manifest case, and every
    // case must have a file. A stray or forgotten file fails here.
    let mut listed: Vec<String> = manifest.cases.iter().map(|case| case.file.clone()).collect();
    listed.sort();
    let mut on_disk: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "manifest.json")
        .collect();
    on_disk.sort();
    assert_eq!(listed, on_disk, "manifest cases and receipt files differ");

    for case in &manifest.cases {
        let json = std::fs::read_to_string(root.join(&case.file)).unwrap();
        let result = SealedReceipt::parse(&json);
        match case.result.as_str() {
            "accept" => {
                result.unwrap_or_else(|error| panic!("{}: {}: {error}", case.file, case.reason));
            }
            "reject" => {
                let error = result.unwrap_err();
                assert_expected_error(case, error);
            }
            result => panic!("unknown manifest result {result}"),
        }
    }
}

fn assert_expected_error(case: &Case, error: ZkarError) {
    let context = || format!("{}: {}", case.file, case.reason);
    match (case.error.as_deref(), error) {
        (
            Some("duplicate_member"),
            ZkarError::DuplicateMember { container, member },
        ) => {
            assert_eq!(container, case.container.as_deref().unwrap(), "{}", context());
            assert_eq!(member, case.member.as_deref().unwrap(), "{}", context());
        }
        (Some("unknown_member"), ZkarError::UnknownMember { container, member }) => {
            assert_eq!(container, case.container.as_deref().unwrap(), "{}", context());
            assert_eq!(member, case.member.as_deref().unwrap(), "{}", context());
        }
        (Some("not_a_string"), ZkarError::NotAString { container, member }) => {
            assert_eq!(container, case.container.as_deref().unwrap(), "{}", context());
            assert_eq!(member, case.member.as_deref().unwrap(), "{}", context());
        }
        (Some("bad_lexical_form"), ZkarError::BadLexicalForm { member, .. }) => {
            assert_eq!(member, case.member.as_deref().unwrap(), "{}", context());
        }
        (Some("profile_mismatch"), ZkarError::Other(message)) => {
            assert_eq!(
                message,
                "top-level profile differs from public_input.profile",
                "{}",
                context()
            );
        }
        (expected, actual) => panic!("{}: expected {expected:?}, got {actual:?}", context()),
    }
}

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../spec/vectors/receipts")
}
