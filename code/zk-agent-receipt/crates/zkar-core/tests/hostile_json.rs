//! attack2: JSON strictness and lexical forms of the sealed-receipt parser.
//! Convention: every test asserts the DEFENCE. A failure printed "GOT THROUGH" is a finding.

use zkar_core::lexical::*;
use zkar_core::statement::{parse_inventory, parse_json_strict, PublicInput, SealedReceipt};
use zkar_core::ZkarError;

const SIG86: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn pi_obj(sig: &str) -> String {
    format!(
        r#"{{"profile":"sar-zk-v0.4b","issuer_key_commitment":"1","log_root":"42","tree_size":"17","log_id":"log.1","log_head_signature":"{sig}","policy_commitment":"7","nullifier_scope":"5","nullifier":"9"}}"#
    )
}

fn receipt(pi: &str, alg: &str, proof: &str) -> String {
    format!(
        r#"{{"profile":"sar-zk-v0.4b","public_input":{pi},"proof":"{proof}","fold_count":"4","algorithm":{alg}}}"#
    )
}

const VK_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ALG: &str = r#"{"arithmetization":"r1cs-nova-uniform","curve":"pasta","proof_encoding":"nova-snark-0.76.0/bincode-2.0.1-legacy","vk_digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#;

#[test]
fn baseline_parses() {
    assert!(SealedReceipt::parse(&receipt(&pi_obj(SIG86), ALG, "AAAA")).is_ok());
}

#[test]
fn escaped_duplicates_at_every_depth() {
    // depth 2: algorithm
    let alg = r#"{"arithmetization":"r1cs-nova-uniform","curve":"pasta","proof_encoding":"nova-snark-0.76.0/bincode-2.0.1-legacy","vk_digest":"0000000000000000000000000000000000000000000000000000000000000000","curve":"pasta"}"#;
    let r = SealedReceipt::parse(&receipt(&pi_obj(SIG86), alg, "AAAA"));
    assert!(
        matches!(r, Err(ZkarError::DuplicateMember { .. })),
        "dup in algorithm GOT THROUGH: {r:?}"
    );
    // depth 2: public_input, escaped differently on both copies
    let pi = pi_obj(SIG86).replacen(
        r#""nullifier":"9""#,
        r#""nullifier":"9","nullifier":"9""#,
        1,
    );
    let r = SealedReceipt::parse(&receipt(&pi, ALG, "AAAA"));
    assert!(
        matches!(r, Err(ZkarError::DuplicateMember { .. })),
        "dup in public_input GOT THROUGH: {r:?}"
    );
    // depth 1: \/ escape
    let s = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen(
        r#""proof":"AAAA""#,
        r#""proof":"AAAA","proof":"AAAA""#,
        1,
    );
    assert!(SealedReceipt::parse(&s).is_err(), "dup proof GOT THROUGH");
    // inside an array inside an unknown member: still must fail (dup or unknown)
    let s = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen("{", r#"{"x":[{"a":1,"a":2}],"#, 1);
    assert!(SealedReceipt::parse(&s).is_err());
    // inventory dup
    let inv = r#"{"tool_artifacts":[],"egress_artifacts":[],"file_artifacts":[],"payment_artifacts":[],"egress_artifacts":["sha256:0000000000000000000000000000000000000000000000000000000000000000"]}"#;
    assert!(
        parse_inventory(inv).is_err(),
        "dup inventory member GOT THROUGH"
    );
}

#[test]
fn lone_surrogates() {
    for bad in [
        r#"{"\ud800":"x"}"#,
        r#"{"a":"\udc00"}"#,
        r#"{"a":"\ud800A"}"#,
    ] {
        let r = parse_json_strict(bad);
        eprintln!("{bad} -> {r:?}");
        assert!(r.is_err(), "lone surrogate GOT THROUGH: {bad}");
    }
    // two different lone-surrogate keys must not collapse into one (or both be accepted)
    let r = parse_json_strict(r#"{"\ud800":"x","\ud801":"y"}"#);
    assert!(r.is_err());
}

#[test]
fn bom_and_trailing_garbage_and_nul() {
    let good = receipt(&pi_obj(SIG86), ALG, "AAAA");
    for bad in [
        format!("\u{feff}{good}"),
        format!("{good}x"),
        format!("{good}\u{0}"),
        format!("{good}{good}"),
    ] {
        let r = SealedReceipt::parse(&bad);
        assert!(r.is_err(), "GOT THROUGH: {:?}", &bad[..8.min(bad.len())]);
    }
    // NUL inside a value
    let s = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen("log.1", "log.1\\u0000", 1);
    assert!(SealedReceipt::parse(&s).is_err());
}

#[test]
fn deep_nesting_does_not_overflow() {
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let r = parse_json_strict(&deep);
    assert!(r.is_err());
    let deep_obj = format!("{}1{}", r#"{"a":"#.repeat(50_000), "}".repeat(50_000));
    assert!(parse_json_strict(&deep_obj).is_err());
}

#[test]
fn numbers_everywhere_rejected() {
    for (k, v) in [
        ("tree_size", "17"),
        ("tree_size", "1.7e1"),
        ("log_root", "42"),
        ("nullifier", "-0"),
        ("tree_size", "1e999"),
    ] {
        let pi = pi_obj(SIG86).replacen(
            &format!(
                r#""{k}":"{}""#,
                if k == "tree_size" {
                    "17"
                } else if k == "log_root" {
                    "42"
                } else {
                    "9"
                }
            ),
            &format!(r#""{k}":{v}"#),
            1,
        );
        assert!(
            PublicInput::parse(&pi).is_err(),
            "number {k}={v} GOT THROUGH"
        );
    }
    let alg = format!(
        r#"{{"arithmetization":"r1cs-nova-uniform","curve":1,"proof_encoding":"nova-snark-0.76.0/bincode-2.0.1-legacy","vk_digest":"{VK_DIGEST}"}}"#
    );
    assert!(SealedReceipt::parse(&receipt(&pi_obj(SIG86), &alg, "AAAA")).is_err());
    assert!(
        SealedReceipt::parse(&receipt(&pi_obj(SIG86), ALG, "AAAA").replacen(
            r#""proof":"AAAA""#,
            r#""proof":0"#,
            1
        ))
        .is_err()
    );
}

#[test]
fn public_input_as_string_or_array_rejected() {
    let quoted = serde_json::to_string(&pi_obj(SIG86)).unwrap();
    assert!(SealedReceipt::parse(&receipt(&quoted, ALG, "AAAA")).is_err());
    assert!(SealedReceipt::parse(&receipt(&format!("[{}]", pi_obj(SIG86)), ALG, "AAAA")).is_err());
    assert!(SealedReceipt::parse(&receipt(&pi_obj(SIG86), "null", "AAAA")).is_err());
}

#[test]
fn field_range_edges() {
    let p = PALLAS_P_DECIMAL;
    // p+1, p with leading zero, 2^256, 78-digit numbers, values that differ only after the first char
    let cases = [
        "28948022309329048855892746252171976963363056481941560715954676764349967630338",
        "028948022309329048855892746252171976963363056481941560715954676764349967630336",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
        "99999999999999999999999999999999999999999999999999999999999999999999999999999",
        "30000000000000000000000000000000000000000000000000000000000000000000000000000",
        p,
    ];
    for c in cases {
        assert!(!is_pallas_field_decimal(c), "GOT THROUGH: {c}");
    }
    for ok in [
        "0",
        "28948022309329048855892746252171976963363056481941560715954676764349967630336",
        "9999999999999999999999999999999999999999999999999999999999999999999999999999",
    ] {
        assert!(is_pallas_field_decimal(ok), "{ok} wrongly rejected");
    }
    // Unicode digits (Arabic-Indic, full-width) must be rejected
    for u in ["\u{0661}", "\u{ff11}", "1\u{0662}"] {
        assert!(!is_decimal(u), "GOT THROUGH: {u:?}");
    }
}

#[test]
fn tree_size_edges() {
    for bad in [
        "0",
        "2147483648",
        "18446744073709551616",
        "99999999999999999999999",
        "+1",
        "01",
    ] {
        let pi =
            pi_obj(SIG86).replacen(r#""tree_size":"17""#, &format!(r#""tree_size":"{bad}""#), 1);
        assert!(
            PublicInput::parse(&pi).is_err(),
            "tree_size {bad} GOT THROUGH"
        );
    }
    let pi = pi_obj(SIG86).replacen(r#""tree_size":"17""#, r#""tree_size":"2147483647""#, 1);
    assert!(PublicInput::parse(&pi).is_ok());
}

#[test]
fn log_id_edges() {
    for bad in [
        "",
        "Log",
        "1log",
        "log\u{0131}",
        "l\u{212a}",
        &"a".repeat(65),
        "log/1",
        "log 1",
    ] {
        let pi = pi_obj(SIG86).replacen(
            r#""log_id":"log.1""#,
            &format!(r#""log_id":{}"#, serde_json::to_string(bad).unwrap()),
            1,
        );
        assert!(
            PublicInput::parse(&pi).is_err(),
            "log_id {bad:?} GOT THROUGH"
        );
    }
}

/// Spec §10: log_head_signature is "Ed25519 over headBytes, 64 bytes".
/// A B64URL of 64 bytes is exactly 86 characters.
#[test]
fn log_head_signature_must_be_64_bytes_at_parse() {
    for bad in ["", "AA", "AAAA", &SIG86[..84], &format!("{SIG86}AA")] {
        let r = SealedReceipt::parse(&receipt(&pi_obj(bad), ALG, "AAAA"));
        assert!(
            r.is_err(),
            "GOT THROUGH: log_head_signature of {} chars accepted by SealedReceipt::parse",
            bad.len()
        );
    }
}

#[test]
fn profile_variants() {
    for bad in [
        "sar-zk-v0.4",
        "SAR-ZK-V0.4A",
        "sar-zk-v0.4a ",
        "sar-zk-v0.4c",
        "sar-zk-v0.3a",
    ] {
        let pi = pi_obj(SIG86).replacen("sar-zk-v0.4b", bad, 1);
        assert!(PublicInput::parse(&pi).is_err(), "{bad} GOT THROUGH");
    }
    // top-level a, inner b
    let s = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen("sar-zk-v0.4b", "sar-zk-v0.4a", 1);
    assert!(SealedReceipt::parse(&s).is_err());
}

#[test]
fn b64url_edges() {
    for bad in [
        "A", "AAAAA", "AA=", "AA==", "A+AA", "A/AA", "AA\n", " AAAA", "AE", "AAB",
    ] {
        assert!(!is_b64url(bad), "GOT THROUGH {bad:?}");
    }
    // exhaustive canonicality check against a reference decoder/encoder
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for len in [2usize, 3] {
        let mut idx = vec![0usize; len];
        loop {
            let s: String = idx.iter().map(|&i| ALPHA[i] as char).collect();
            // reference: decode then re-encode
            let mut bits = 0u32;
            let mut val = 0u32;
            let mut out = vec![];
            for &i in &idx {
                val = (val << 6) | i as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((val >> bits) as u8);
                }
            }
            let canonical = val & ((1 << bits) - 1) == 0;
            assert_eq!(is_b64url(&s), canonical, "{s}");
            let mut k = len;
            loop {
                if k == 0 {
                    break;
                }
                k -= 1;
                idx[k] += 1;
                if idx[k] < 64 {
                    break;
                }
                idx[k] = 0;
                if k == 0 {
                    k = usize::MAX;
                    break;
                }
            }
            if k == usize::MAX {
                break;
            }
        }
    }
}

#[test]
fn fold_count_is_a_canonical_bounded_power_of_two() {
    for valid in ["4", "8", "16", "1048576"] {
        let json = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen(
            r#""fold_count":"4""#,
            &format!(r#""fold_count":"{valid}""#),
            1,
        );
        assert!(
            SealedReceipt::parse(&json).is_ok(),
            "valid fold count {valid}"
        );
    }
    for bad in [
        "",
        "0",
        "1",
        "2",
        "3",
        "5",
        "6",
        "1048577",
        "2097152",
        "04",
        "+4",
        "4.0",
        "1e2",
        "-4",
        " 4",
        "4 ",
        "999999999999999999999999999999",
    ] {
        let json = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen(
            r#""fold_count":"4""#,
            &format!(r#""fold_count":"{bad}""#),
            1,
        );
        assert!(
            matches!(
                SealedReceipt::parse(&json),
                Err(ZkarError::BadLexicalForm {
                    member: "fold_count",
                    ..
                })
            ),
            "fold_count {bad:?} GOT THROUGH"
        );
    }
    let numeric = receipt(&pi_obj(SIG86), ALG, "AAAA").replacen(
        r#""fold_count":"4""#,
        r#""fold_count":4"#,
        1,
    );
    assert!(matches!(
        SealedReceipt::parse(&numeric),
        Err(ZkarError::NotAString {
            member: "fold_count",
            ..
        })
    ));
}

#[test]
fn every_algorithm_member_is_strict() {
    let baseline: serde_json::Value =
        serde_json::from_str(&receipt(&pi_obj(SIG86), ALG, "AAAA")).unwrap();
    for member in ["arithmetization", "curve", "proof_encoding", "vk_digest"] {
        let mut missing = baseline.clone();
        missing["algorithm"].as_object_mut().unwrap().remove(member);
        assert!(matches!(
            SealedReceipt::parse(&serde_json::to_string(&missing).unwrap()),
            Err(ZkarError::MissingMember {
                container: "Algorithm",
                ..
            })
        ));
    }

    let mut unknown = baseline.clone();
    unknown["algorithm"]["extra"] = "x".into();
    assert!(matches!(
        SealedReceipt::parse(&serde_json::to_string(&unknown).unwrap()),
        Err(ZkarError::UnknownMember {
            container: "Algorithm",
            ..
        })
    ));

    for bad in ["r1cs-supernova ", "r1cs-nova", "R1CS-NOVA-UNIFORM", ""] {
        let mut value = baseline.clone();
        value["algorithm"]["arithmetization"] = bad.into();
        assert!(SealedReceipt::parse(&serde_json::to_string(&value).unwrap()).is_err());
    }
    let mut reserved = baseline.clone();
    reserved["algorithm"]["arithmetization"] = "r1cs-supernova".into();
    assert!(SealedReceipt::parse(&serde_json::to_string(&reserved).unwrap()).is_ok());

    for bad in ["PASTA", "pallas", "vesta", ""] {
        let mut value = baseline.clone();
        value["algorithm"]["curve"] = bad.into();
        assert!(SealedReceipt::parse(&serde_json::to_string(&value).unwrap()).is_err());
    }
    for bad in [
        "nova-snark-0.76.0/bincode-2.0.1-standard",
        "nova-snark-0.75.0/bincode-2.0.1-legacy",
        "bincode-2.0.1-legacy",
        "",
    ] {
        let mut value = baseline.clone();
        value["algorithm"]["proof_encoding"] = bad.into();
        assert!(SealedReceipt::parse(&serde_json::to_string(&value).unwrap()).is_err());
    }
    for bad in [
        "",
        "0",
        "000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000A",
        "g000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let mut value = baseline.clone();
        value["algorithm"]["vk_digest"] = bad.into();
        assert!(SealedReceipt::parse(&serde_json::to_string(&value).unwrap()).is_err());
    }
}

#[test]
fn huge_input_is_bounded() {
    // 64 MiB string in an unknown member: the parser must refuse it. We only time it.
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(64 << 20));
    let t = std::time::Instant::now();
    let r = SealedReceipt::parse(&big);
    eprintln!(
        "64 MiB unknown member parsed to {:?} in {:?}",
        r.as_ref().map(|_| ()),
        t.elapsed()
    );
    assert!(r.is_err());
}
