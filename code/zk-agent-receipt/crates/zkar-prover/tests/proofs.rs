//! Actual Nova/Spartan integration tests, run explicitly in release mode.
use ff::Field;
use zkar_prover::{
    issuance::Fixture,
    proofs::{self, Compressed},
    relation::UniformCircuit,
    F,
};

#[test]
#[ignore = "real cryptographic proof; run cargo test --release --target aarch64-apple-darwin -p zkar-prover --test proofs -- --ignored"]
fn compressed_roundtrip_public_bindings_and_mandatory_halt() {
    let fixture = Fixture::benchmark_deterministic(1, 4, 2, 0x5341525a4b).unwrap();
    let mut circuits: Vec<_> = fixture
        .uniform_steps()
        .into_iter()
        .map(|s| s.circuit)
        .collect();
    assert_eq!(circuits.len(), 4);
    let pp = proofs::setup(&circuits[0]).unwrap();
    let (pk, raw_vk) = Compressed::setup(&pp).unwrap();
    let digest = proofs::vk_digest(&raw_vk).unwrap();
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    let vk_bytes = proofs::encode(&raw_vk).unwrap();
    let (vk_copy, _): (proofs::CompressionVerifierKey<UniformCircuit>, usize) =
        bincode::serde::decode_from_slice(&vk_bytes, bincode::config::legacy()).unwrap();
    assert!(proofs::PinnedVerifierKey::new(vk_copy, &wrong_digest).is_err());
    let vk = proofs::PinnedVerifierKey::new(raw_vk, &digest).unwrap();
    let recursive = proofs::fold(&pp, &circuits, &fixture.initial_state()).unwrap();
    assert_eq!(
        recursive.verify(&pp, 4, &fixture.initial_state()).unwrap(),
        fixture.expected_final_state()
    );
    let proof = Compressed::prove(&pp, &pk, &recursive).unwrap();
    let bytes = proofs::encode(&proof).unwrap();
    let (proof, consumed): (Compressed<UniformCircuit>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
    assert_eq!(consumed, bytes.len());
    let public = fixture.public_bind.to_array();
    proofs::verify(&proof, &vk, 4, &public, fixture.nullifier).unwrap();
    // Exercise the existing strict Ed25519 verifier together with the real
    // compressed proof, binding the signed head to the same root and size.
    use ed25519_dalek::{Signer, SigningKey};
    let log_key = SigningKey::from_bytes(&[0x42; 32]);
    let log_public_key = log_key.verifying_key().to_bytes();
    let context = proofs::VerifierContext {
        public_bind: public,
        nullifier: fixture.nullifier,
        log_id: "test.log",
        log_public_key: &log_public_key,
    };
    let mut signature = log_key.sign(&context.log_head_bytes().unwrap()).to_bytes();
    proofs::verify_authenticated(&proof, &vk, 4, &context, &signature).unwrap();
    signature[0] ^= 1;
    assert!(proofs::verify_authenticated(&proof, &vk, 4, &context, &signature).is_err());
    for i in 0..public.len() {
        let mut tampered = public;
        tampered[i] += F::ONE;
        assert!(
            proofs::verify(&proof, &vk, 4, &tampered, fixture.nullifier).is_err(),
            "public binding {i}"
        );
    }
    assert!(proofs::verify(&proof, &vk, 4, &public, fixture.nullifier + F::ONE).is_err());
    assert!(proofs::verify(&proof, &vk, 8, &public, fixture.nullifier).is_err());

    // Replace FINAL with another padding step. The fold count remains a valid
    // public bucket, and the raw Nova proof is valid: only receipt-level HALT
    // verification can reject this otherwise valid truncated computation.
    let final_circuit = circuits[3].clone();
    circuits[3] = circuits[2].clone();
    let unfinished = proofs::fold(&pp, &circuits, &fixture.initial_state()).unwrap();
    let unfinished = Compressed::prove(&pp, &pk, &unfinished).unwrap();
    let state = unfinished
        .verify(vk.key(), 4, &fixture.initial_state())
        .unwrap();
    assert_eq!(state[0], F::ONE);
    assert!(proofs::verify(&unfinished, &vk, 4, &public, fixture.nullifier).is_err());

    // A malformed issuer signature must fail actual proving or compressed
    // verification, not merely a native preflight predicate.
    circuits[3] = final_circuit;
    circuits[3].final_witness.signature.s += zkar_prover::schnorr::Scalar::ONE;
    let bad_result = proofs::fold(&pp, &circuits, &fixture.initial_state())
        .map_err(|e| format!("recursive proving: {e}"))
        .and_then(|r| Compressed::prove(&pp, &pk, &r).map_err(|e| format!("compression: {e}")))
        .and_then(|p| {
            proofs::verify(&p, &vk, 4, &public, fixture.nullifier)
                .map_err(|e| format!("compressed verification: {e}"))
        });
    eprintln!("bad issuer signature rejected by {bad_result:?}");
    assert!(bad_result.is_err());
}

#[test]
#[ignore = "real cryptographic proofs; run the release proof integration suite"]
fn direct_baselines_are_real_spartan() {
    // Both direct baselines use this proof type. Check that their reported
    // encoding transports a verifiable proof, rather than only counting bytes.
    type DirectCircuit = proofs::Sequence<zkar_prover::relation::BranchCircuit>;
    let fixture = Fixture::benchmark_deterministic(1, 4, 2, 0x5341525a4b).unwrap();
    let circuit = DirectCircuit {
        circuits: fixture
            .branch_steps_unpadded()
            .into_iter()
            .map(|s| s.circuit)
            .collect(),
    };
    // Account for the actual public-I/O wrapper, not a guessed overhead.
    use nova_snark::frontend::Circuit;
    let application_count = proofs::constraint_count(&circuit).unwrap();
    let mut shape = nova_snark::frontend::shape_cs::ShapeCS::<zkar_prover::E1>::new();
    nova_snark::spartan::direct::DirectCircuit::<zkar_prover::E1, _>::new(None, circuit.clone())
        .synthesize(&mut shape)
        .unwrap();
    assert_eq!(shape.num_constraints(), application_count + 18);
    let (pk, vk) = proofs::Direct::setup(circuit.clone()).unwrap();
    let proof = proofs::Direct::prove(&pk, circuit, &fixture.initial_state()).unwrap();
    let bytes = proofs::encode(&proof).unwrap();
    let (decoded, consumed): (proofs::Direct<DirectCircuit>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
    assert_eq!(consumed, bytes.len());
    let io: Vec<_> = fixture
        .initial_state()
        .into_iter()
        .chain(fixture.expected_final_state())
        .collect();
    decoded.verify(&vk, &io).unwrap();
}
