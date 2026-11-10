//! Malformed proof shapes.
//!
//! The test makes one real proof. It then changes the length of each vector in
//! the proof, one at a time, and checks the result. The verifier must reject
//! every changed proof. It must not accept one, and it must not panic.
//!
//! The test needs a release build, so it is ignored by default.

use std::{
    any::Any,
    panic::{catch_unwind, AssertUnwindSafe},
};

use serde_json::Value;
use zkar_prover::{
    issuance::Fixture,
    proofs::{self, Compressed, PinnedVerifierKey},
    relation::UniformCircuit,
    sealed::MAX_PROOF_BYTES,
};

#[derive(Clone, Debug)]
enum PathPart {
    Key(String),
    Index(usize),
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Clear,
    RemoveFirst,
    DuplicateFirst,
}

impl Mutation {
    fn name(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::RemoveFirst => "remove-first",
            Self::DuplicateFirst => "duplicate-first",
        }
    }
}

fn array_paths(value: &Value, prefix: &mut Vec<PathPart>, found: &mut Vec<Vec<PathPart>>) {
    match value {
        Value::Array(values) => {
            if !values.is_empty() {
                found.push(prefix.clone());
            }
            for (index, child) in values.iter().enumerate() {
                prefix.push(PathPart::Index(index));
                array_paths(child, prefix, found);
                prefix.pop();
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                prefix.push(PathPart::Key(key.clone()));
                array_paths(child, prefix, found);
                prefix.pop();
            }
        }
        _ => {}
    }
}

fn at_path<'a>(mut value: &'a mut Value, path: &[PathPart]) -> Option<&'a mut Value> {
    for part in path {
        value = match part {
            PathPart::Key(key) => value.as_object_mut()?.get_mut(key)?,
            PathPart::Index(index) => value.as_array_mut()?.get_mut(*index)?,
        };
    }
    Some(value)
}

fn mutate(value: &mut Value, path: &[PathPart], mutation: Mutation) -> bool {
    let Some(Value::Array(values)) = at_path(value, path) else {
        return false;
    };
    if values.is_empty() {
        return false;
    }
    match mutation {
        Mutation::Clear => values.clear(),
        Mutation::RemoveFirst => {
            values.remove(0);
        }
        Mutation::DuplicateFirst => values.push(values[0].clone()),
    }
    true
}

fn path_name(path: &[PathPart]) -> String {
    let mut name = String::from("$");
    for part in path {
        match part {
            PathPart::Key(key) => {
                name.push('.');
                name.push_str(key);
            }
            PathPart::Index(index) => name.push_str(&format!("[{index}]")),
        }
    }
    name
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[test]
#[ignore = "real release-mode Nova proof"]
fn malformed_proof_shapes_are_rejected_without_a_panic() {
    let fixture = Fixture::benchmark_deterministic(1, 1, 0, 0x5341_522d_5a4b).unwrap();
    let circuits: Vec<_> = fixture
        .uniform_steps()
        .into_iter()
        .map(|step| step.circuit)
        .collect();
    assert_eq!(circuits.len(), 4);

    let parameters = proofs::setup(&circuits[0]).unwrap();
    let (prover_key, raw_vk) = Compressed::setup(&parameters).unwrap();
    let digest = proofs::vk_digest(&raw_vk).unwrap();
    let verifier_key = PinnedVerifierKey::new(raw_vk, &digest).unwrap();
    let recursive = proofs::fold(&parameters, &circuits, &fixture.initial_state()).unwrap();
    let proof = Compressed::prove(&parameters, &prover_key, &recursive).unwrap();
    let original_bytes = proofs::encode(&proof).unwrap();
    assert!(original_bytes.len() <= MAX_PROOF_BYTES);
    proofs::verify(
        &proof,
        &verifier_key,
        circuits.len(),
        &fixture.public_bind.to_array(),
        fixture.nullifier,
    )
    .expect("the unchanged proof must verify");

    let original = serde_json::to_value(&proof)
        .expect("the serializable compressed proof must have a JSON structural view");
    let original_primary_evals = original["snark_primary"]["evals_batch"]
        .as_array()
        .map_or(0, Vec::len);
    let mut paths = Vec::new();
    array_paths(&original, &mut Vec::new(), &mut paths);
    assert!(
        !paths.is_empty(),
        "compressed proof JSON contained no arrays"
    );

    let public_bind = fixture.public_bind.to_array();
    let mut panics = Vec::new();
    let mut accepted = Vec::new();
    let mut attempted = 0usize;
    let mut exercised = 0usize;
    let mut too_large = 0usize;
    let mut decode_rejected = 0usize;
    for path in paths {
        for mutation in [
            Mutation::Clear,
            Mutation::RemoveFirst,
            Mutation::DuplicateFirst,
        ] {
            attempted += 1;
            let mut candidate = original.clone();
            assert!(mutate(&mut candidate, &path, mutation));
            let label = format!("{}:{}", path_name(&path), mutation.name());

            // Skip a change that Serde rejects. The test is about shapes that
            // still decode into a proof value.
            let Ok(candidate) = serde_json::from_value::<Compressed<UniformCircuit>>(candidate)
            else {
                continue;
            };
            exercised += 1;
            let bytes = proofs::encode(&candidate).expect("typed proof must bincode encode");
            if bytes.len() > MAX_PROOF_BYTES {
                too_large += 1;
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                let (decoded, consumed): (Compressed<UniformCircuit>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
                        .map_err(|error| format!("bincode decode: {error}"))?;
                if consumed != bytes.len() {
                    return Err("bincode decoder left trailing bytes".to_owned());
                }
                proofs::verify(
                    &decoded,
                    &verifier_key,
                    circuits.len(),
                    &public_bind,
                    fixture.nullifier,
                )
                .map_err(|error| format!("Nova verification: {error}"))
            }));
            match result {
                Err(payload) => {
                    panics.push(format!("{label}: {}", panic_message(payload.as_ref())))
                }
                Ok(Ok(())) => accepted.push(label),
                Ok(Err(_)) => decode_rejected += 1,
            }
        }
    }

    eprintln!(
        "malformed proof shapes: original_bytes={}, primary_evals_batch={}, array_paths={}, attempted={}, typed={}, too_large={}, rejected={}, panics={}, accepted={}",
        original_bytes.len(),
        original_primary_evals,
        attempted / 3,
        attempted,
        exercised,
        too_large,
        decode_rejected,
        panics.len(),
        accepted.len(),
    );
    if !panics.is_empty() {
        eprintln!("panic paths: {panics:?}");
    }
    if !accepted.is_empty() {
        eprintln!("accepted mutated shapes: {accepted:?}");
    }
    assert!(
        exercised > 0,
        "no mutated array shape survived JSON deserialization"
    );
    assert!(panics.is_empty(), "panic paths: {panics:?}");
    assert!(
        accepted.is_empty(),
        "mutated proof shapes accepted: {accepted:?}"
    );
}
