//! Checks the SAR-ZK Poseidon vectors and the plain circuit mirror.

use ff::{Field, PrimeField};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zkar_circuit::{Entry, FieldElement, FieldHasher, Kind, Statement};
use zkar_prover::{
    poseidon,
    relation::{self, EntryWitness, PolicyOpening, StatementWitness},
    F,
};

const DOMAINS: [&str; 14] = [
    "SAR-ZK statement",
    "SAR-ZK leaf",
    "SAR-ZK node",
    "SAR-ZK empty",
    "SAR-ZK transcript",
    "SAR-ZK step",
    "SAR-ZK allow",
    "SAR-ZK policy",
    "SAR-ZK nk",
    "SAR-ZK nullifier",
    "SAR-ZK scope",
    "SAR-ZK acc",
    "SAR-ZK issuer",
    "SAR-ZK schnorr",
];

#[derive(Debug, Serialize, Deserialize)]
struct VectorFile {
    field_modulus: String,
    domains: Vec<DomainVectors>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DomainVectors {
    domain: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vector {
    name: String,
    inputs: Vec<String>,
    output: String,
}

#[test]
fn every_vector_matches_the_native_sponge() {
    let file = read_vectors();
    assert_eq!(file.field_modulus, zkar_core::lexical::PALLAS_P_DECIMAL);
    assert_eq!(file.domains.len(), DOMAINS.len());

    for expected_domain in DOMAINS {
        let domain = file
            .domains
            .iter()
            .find(|entry| entry.domain == expected_domain)
            .unwrap_or_else(|| panic!("missing domain {expected_domain}"));
        assert!(domain.vectors.len() >= 3, "domain {expected_domain}");
        for vector in &domain.vectors {
            let inputs = parse_fields(&vector.inputs);
            let actual = poseidon::hash_native(expected_domain, &inputs);
            assert_eq!(
                decimal(actual),
                vector.output,
                "domain {expected_domain}, vector {}",
                vector.name
            );
        }
    }
}

#[test]
fn plain_mirror_and_native_helpers_use_the_same_inputs() {
    let file = read_vectors();
    for domain in &file.domains {
        for vector in &domain.vectors {
            let inputs = parse_fields(&vector.inputs);
            let Some(native) = native_helper_hash(&domain.domain, &inputs) else {
                continue;
            };
            assert_eq!(
                decimal(native),
                vector.output,
                "domain {}, vector {}",
                domain.domain,
                vector.name
            );
            if let Some(mirror) = mirror_hash(&domain.domain, &inputs) {
                assert_eq!(
                    mirror,
                    native,
                    "domain {}, vector {}",
                    domain.domain,
                    vector.name
                );
            }
        }
    }
}

/// The mirror takes typed inputs for the step and policy hashes: an entry
/// list, and a flag with a bound. The flat vectors cannot drive those two
/// functions, so this test calls them with typed values.
#[test]
fn plain_mirror_matches_native_step_and_policy() {
    let task_binding = F::from(11);
    let d_hi = F::from(12);
    let d_lo = F::from(13);
    let entry = Entry {
        kind: Kind::Payment,
        d_hi: MirrorField(d_hi),
        d_lo: MirrorField(d_lo),
    };
    let mirror =
        zkar_circuit::transcript::<MirrorHasher>(MirrorField(task_binding), &[entry]).0;
    let native = relation::transcript_step_native(
        relation::transcript_start_native(task_binding),
        F::ONE,
        &EntryWitness {
            kind: F::from(Kind::Payment as u64),
            d_hi,
            d_lo,
            allow_index: F::ZERO,
            allow_path: [F::ZERO; relation::ALLOWLIST_DEPTH],
        },
    );
    assert_eq!(mirror, native);

    let root = F::from(21);
    let mirror = zkar_circuit::policy_commitment::<MirrorHasher>(MirrorField(root), true, 7).0;
    let native = relation::policy_commitment_native(PolicyOpening {
        allowlist_root: root,
        egress_allowed: F::ONE,
        payment_bound: F::from(7),
    });
    assert_eq!(mirror, native);
}

/// Rebuilds the vector file from the native implementation and compares it
/// with the checked-in file. Set `ZKAR_WRITE_VECTORS=1` to write the file.
#[test]
fn checked_in_vectors_match_the_generator() {
    let zero = F::ZERO;
    let one = F::ONE;
    let p_minus_one = -F::ONE;
    let cases = [
        ("empty", vec![]),
        ("zero", vec![zero]),
        ("one", vec![one]),
        ("p_minus_one", vec![p_minus_one]),
        (
            "mixed_even",
            vec![zero, one, p_minus_one, F::from(42)],
        ),
        (
            "mixed_odd",
            vec![p_minus_one, F::from(42), zero, one, F::from(123456789)],
        ),
    ];
    let domains = DOMAINS
        .into_iter()
        .map(|domain| {
            let mut vectors: Vec<Vector> = cases
                .iter()
                .map(|(name, inputs)| Vector {
                    name: (*name).to_owned(),
                    inputs: inputs.iter().copied().map(decimal).collect(),
                    output: decimal(poseidon::hash_native(domain, inputs)),
                })
                .collect();
            let arity = profile_arity(domain);
            if !cases.iter().any(|(_, inputs)| inputs.len() == arity) {
                let inputs: Vec<F> = (0..arity)
                    .map(|index| [zero, one, p_minus_one, F::from(42)][index % 4])
                    .collect();
                vectors.push(Vector {
                    name: "profile_arity".to_owned(),
                    inputs: inputs.iter().copied().map(decimal).collect(),
                    output: decimal(poseidon::hash_native(domain, &inputs)),
                });
            }
            DomainVectors {
                domain: domain.to_owned(),
                vectors,
            }
        })
        .collect();
    let file = VectorFile {
        field_modulus: zkar_core::lexical::PALLAS_P_DECIMAL.to_owned(),
        domains,
    };
    let path = vectors_path();
    let text = serde_json::to_string_pretty(&file).unwrap() + "\n";
    if std::env::var_os("ZKAR_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(path).unwrap(), text);
    }
}

fn profile_arity(domain: &str) -> usize {
    match domain {
        "SAR-ZK statement" | "SAR-ZK step" | "SAR-ZK schnorr" => 5,
        "SAR-ZK leaf" | "SAR-ZK transcript" => 1,
        "SAR-ZK node" | "SAR-ZK allow" | "SAR-ZK nk" | "SAR-ZK nullifier"
        | "SAR-ZK scope" | "SAR-ZK issuer" => 2,
        "SAR-ZK empty" => 0,
        "SAR-ZK policy" => 3,
        "SAR-ZK acc" => 7,
        _ => panic!("unknown domain {domain}"),
    }
}

fn read_vectors() -> VectorFile {
    let text = std::fs::read_to_string(vectors_path()).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../spec/vectors/poseidon.json")
}

fn parse_fields(values: &[String]) -> Vec<F> {
    values
        .iter()
        .map(|value| {
            let field = F::from_str_vartime(value)
                .unwrap_or_else(|| panic!("noncanonical field element {value}"));
            assert_eq!(decimal(field), *value);
            field
        })
        .collect()
}

fn decimal(value: F) -> String {
    BigUint::from_bytes_le(value.to_repr().as_ref()).to_str_radix(10)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MirrorField(F);

impl FieldElement for MirrorField {
    fn from_u64(value: u64) -> Self {
        Self(F::from(value))
    }

    fn from_be_bytes16(bytes: &[u8; 16]) -> Self {
        Self(bytes.iter().fold(F::ZERO, |value, byte| {
            value * F::from(256) + F::from(*byte as u64)
        }))
    }
}

struct MirrorHasher;

impl FieldHasher for MirrorHasher {
    type F = MirrorField;

    fn hash(domain: &'static str, input: &[Self::F]) -> Self::F {
        MirrorField(poseidon::hash_native(
            domain,
            &input.iter().map(|value| value.0).collect::<Vec<_>>(),
        ))
    }
}

fn mirror_hash(domain: &str, inputs: &[F]) -> Option<F> {
    let values: Vec<MirrorField> = inputs.iter().copied().map(MirrorField).collect();
    let value = match (domain, inputs.len()) {
        ("SAR-ZK statement", 5) => Statement {
            profile_tag: values[0],
            task_binding: values[1],
            step_count: values[2],
            transcript: values[3],
            nk_commitment: values[4],
        }
        .h_s::<MirrorHasher>()
        .0,
        ("SAR-ZK leaf", 1) => zkar_circuit::log_leaf::<MirrorHasher>(values[0]).0,
        ("SAR-ZK node", 2) => zkar_circuit::tree_root::<MirrorHasher>(&values, 1).0,
        ("SAR-ZK empty", 0) => zkar_circuit::empty_subtrees::<MirrorHasher>(0)[0].0,
        ("SAR-ZK transcript", 1) => {
            zkar_circuit::transcript::<MirrorHasher>(values[0], &[]).0
        }
        ("SAR-ZK allow", 2) => zkar_circuit::allow_leaf::<MirrorHasher>(&Entry {
            kind: Kind::Tool,
            d_hi: values[0],
            d_lo: values[1],
        })
        .0,
        ("SAR-ZK nk", 2) => zkar_circuit::nk_commitment::<MirrorHasher>(values[0], values[1]).0,
        ("SAR-ZK nullifier", 2) => {
            zkar_circuit::nullifier::<MirrorHasher>(values[0], values[1]).0
        }
        _ => return None,
    };
    Some(value)
}

fn native_helper_hash(domain: &str, inputs: &[F]) -> Option<F> {
    let value = match (domain, inputs.len()) {
        ("SAR-ZK statement", 5) => relation::statement_hash_native(StatementWitness {
            profile_tag: inputs[0],
            task_binding: inputs[1],
            step_count: inputs[2],
            transcript: inputs[3],
            nk_commitment: inputs[4],
        }),
        ("SAR-ZK leaf", 1) => relation::log_leaf_native(inputs[0]),
        ("SAR-ZK node", 2) | ("SAR-ZK empty", 0) => {
            poseidon::hash_native(domain, inputs)
        }
        ("SAR-ZK transcript", 1) => relation::transcript_start_native(inputs[0]),
        ("SAR-ZK step", 5) => relation::transcript_step_native(
            inputs[0],
            inputs[1],
            &EntryWitness {
                kind: inputs[2],
                d_hi: inputs[3],
                d_lo: inputs[4],
                allow_index: F::ZERO,
                allow_path: [F::ZERO; relation::ALLOWLIST_DEPTH],
            },
        ),
        ("SAR-ZK allow", 2) => relation::allow_leaf_native(inputs[0], inputs[1]),
        ("SAR-ZK policy", 3) => relation::policy_commitment_native(PolicyOpening {
            allowlist_root: inputs[0],
            egress_allowed: inputs[1],
            payment_bound: inputs[2],
        }),
        ("SAR-ZK nk", 2) => relation::nk_commitment_native(inputs[0], inputs[1]),
        ("SAR-ZK nullifier", 2) => relation::nullifier_native(inputs[0], inputs[1]),
        _ => return None,
    };
    Some(value)
}
