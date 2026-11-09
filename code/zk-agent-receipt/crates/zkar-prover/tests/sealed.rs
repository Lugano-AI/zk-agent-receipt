use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ff::Field;
use zkar_core::statement::{
    Algorithm, PublicInput, SealedReceipt, ARITHMETIZATION_NOVA_UNIFORM,
    ARITHMETIZATION_SUPERNOVA_RESERVED, CURVE_PASTA, PROOF_ENCODING_NOVA_BINCODE_LEGACY,
};
use zkar_prover::{
    issuance::Fixture,
    presentation::PresentationProof,
    proofs::{self, Compressed, PinnedVerifierKey},
    replay::InMemoryReplaySet,
    sealed::{self, Outcome, TrustAnchor, MAX_PROOF_BYTES},
    F,
};

fn receipt_for(
    fixture: &Fixture,
    presentation: &PresentationProof,
    digest: &[u8; 32],
    log_key: &SigningKey,
) -> SealedReceipt {
    let bind = fixture.public_bind;
    let mut public_input = PublicInput {
        profile: zkar_core::PROFILE_B.to_owned(),
        issuer_key_commitment: sealed::field_decimal(bind.issuer_key_commitment),
        log_root: sealed::field_decimal(bind.log_root),
        tree_size: sealed::field_decimal(bind.tree_size),
        log_id: "test.log".to_owned(),
        log_head_signature: String::new(),
        policy_commitment: sealed::field_decimal(bind.policy_commitment),
        nullifier_scope: sealed::field_decimal(bind.nullifier_scope),
        nullifier: sealed::field_decimal(fixture.nullifier),
    };
    let signature = log_key.sign(&zkar_core::verify::canonical_head_bytes(&public_input).unwrap());
    public_input.log_head_signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    SealedReceipt {
        profile: zkar_core::PROFILE_B.to_owned(),
        public_input,
        proof: sealed::encode_proof(presentation.proof()).unwrap(),
        fold_count: presentation.fold_count().to_string(),
        algorithm: Algorithm {
            arithmetization: ARITHMETIZATION_NOVA_UNIFORM.to_owned(),
            curve: CURVE_PASTA.to_owned(),
            proof_encoding: PROOF_ENCODING_NOVA_BINCODE_LEGACY.to_owned(),
            vk_digest: sealed::digest_hex(digest),
        },
    }
}

fn increment_decimal(value: &str) -> String {
    sealed::field_decimal(sealed::parse_field_decimal(value).unwrap() + F::ONE)
}

#[test]
#[ignore = "real release-mode Nova proofs"]
fn sealed_receipt_verifies_rejects_tampering_and_detects_replay() {
    let fixture = Fixture::benchmark_deterministic(1, 4, 2, 0x5341525a4b).unwrap();
    let circuits: Vec<_> = fixture
        .uniform_steps()
        .into_iter()
        .map(|step| step.circuit)
        .collect();
    let parameters = proofs::setup(&circuits[0]).unwrap();
    let (prover_key, raw_vk) = Compressed::setup(&parameters).unwrap();
    let digest = proofs::vk_digest(&raw_vk).unwrap();
    let pinned = PinnedVerifierKey::new(raw_vk, &digest).unwrap();
    let log_key = SigningKey::from_bytes(&[0x42; 32]);
    let log_public_key = log_key.verifying_key().to_bytes();
    let presentation = fixture.present(&parameters, &prover_key).unwrap();
    let receipt = receipt_for(&fixture, &presentation, &digest, &log_key);
    assert!(proofs::encode(presentation.proof()).unwrap().len() <= MAX_PROOF_BYTES);
    let json = serde_json::to_string(&receipt).unwrap();
    assert_eq!(SealedReceipt::parse(&json).unwrap(), receipt);

    let replay = InMemoryReplaySet::new();
    let verify = |candidate: &SealedReceipt, replay: &InMemoryReplaySet| {
        sealed::verify_sealed_receipt(
            candidate,
            &pinned,
            &digest,
            TrustAnchor {
                log_id: "test.log",
                ed25519_public_key: &log_public_key,
            },
            fixture.public_bind.policy_commitment,
            fixture.public_bind.nullifier_scope,
            fixture.public_bind.issuer_key_commitment,
            replay,
        )
    };
    assert_eq!(verify(&receipt, &replay).unwrap(), Outcome::Passed);
    assert_eq!(verify(&receipt, &replay).unwrap(), Outcome::ReplaySuspected);

    let second = fixture.present(&parameters, &prover_key).unwrap();
    assert_ne!(presentation.rho(), second.rho());
    assert_eq!(presentation.fold_count(), second.fold_count());
    let second_receipt = receipt_for(&fixture, &second, &digest, &log_key);
    assert_eq!(
        verify(&second_receipt, &InMemoryReplaySet::new()).unwrap(),
        Outcome::Passed
    );
    assert_eq!(
        second_receipt.public_input.nullifier,
        receipt.public_input.nullifier
    );

    let reject = |candidate: &SealedReceipt, name: &str| {
        let result = verify(candidate, &InMemoryReplaySet::new());
        assert!(result.is_err(), "{name} was accepted: {result:?}");
    };

    let mut tampered = receipt.clone();
    tampered.profile = zkar_core::PROFILE_A.to_owned();
    reject(&tampered, "top-level profile");
    tampered = receipt.clone();
    tampered.public_input.profile = zkar_core::PROFILE_A.to_owned();
    reject(&tampered, "public-input profile");
    tampered = receipt.clone();
    tampered.public_input.issuer_key_commitment =
        increment_decimal(&receipt.public_input.issuer_key_commitment);
    reject(&tampered, "issuer key commitment");
    tampered = receipt.clone();
    tampered.public_input.log_root = increment_decimal(&receipt.public_input.log_root);
    reject(&tampered, "log root");
    tampered = receipt.clone();
    tampered.public_input.tree_size = increment_decimal(&receipt.public_input.tree_size);
    reject(&tampered, "tree size");
    tampered = receipt.clone();
    tampered.public_input.log_id = "other.log".to_owned();
    reject(&tampered, "log id");
    tampered = receipt.clone();
    tampered.public_input.policy_commitment =
        increment_decimal(&receipt.public_input.policy_commitment);
    reject(&tampered, "policy commitment");
    tampered = receipt.clone();
    tampered.public_input.nullifier_scope =
        increment_decimal(&receipt.public_input.nullifier_scope);
    reject(&tampered, "nullifier scope");
    tampered = receipt.clone();
    tampered.public_input.nullifier = increment_decimal(&receipt.public_input.nullifier);
    reject(&tampered, "nullifier");

    tampered = receipt.clone();
    let mut signature = URL_SAFE_NO_PAD
        .decode(&receipt.public_input.log_head_signature)
        .unwrap();
    signature[0] ^= 1;
    tampered.public_input.log_head_signature = URL_SAFE_NO_PAD.encode(signature);
    reject(&tampered, "log-head signature");

    tampered = receipt.clone();
    let mut proof = URL_SAFE_NO_PAD.decode(&receipt.proof).unwrap();
    proof[0] ^= 1;
    tampered.proof = URL_SAFE_NO_PAD.encode(proof);
    reject(&tampered, "proof bytes");

    tampered = receipt.clone();
    let mut trailing = URL_SAFE_NO_PAD.decode(&receipt.proof).unwrap();
    trailing.push(0);
    tampered.proof = URL_SAFE_NO_PAD.encode(trailing);
    reject(&tampered, "proof trailing bytes");

    tampered = receipt.clone();
    tampered.fold_count = "8".to_owned();
    reject(&tampered, "fold count");
    tampered = receipt.clone();
    tampered.algorithm.vk_digest = sealed::digest_hex(&[0x55; 32]);
    reject(&tampered, "receipt key digest");
    tampered = receipt.clone();
    tampered.algorithm.arithmetization = ARITHMETIZATION_SUPERNOVA_RESERVED.to_owned();
    reject(&tampered, "reserved SuperNova identifier");
    tampered = receipt.clone();
    tampered.algorithm.curve = "other".to_owned();
    reject(&tampered, "curve");
    tampered = receipt.clone();
    tampered.algorithm.proof_encoding = "other".to_owned();
    reject(&tampered, "proof encoding identifier");

    assert!(sealed::verify_sealed_receipt(
        &receipt,
        &pinned,
        &[0x55; 32],
        TrustAnchor {
            log_id: "test.log",
            ed25519_public_key: &log_public_key,
        },
        fixture.public_bind.policy_commitment,
        fixture.public_bind.nullifier_scope,
        fixture.public_bind.issuer_key_commitment,
        &InMemoryReplaySet::new(),
    )
    .is_err());

    for (name, policy, scope, issuer) in [
        (
            "expected policy",
            fixture.public_bind.policy_commitment + F::ONE,
            fixture.public_bind.nullifier_scope,
            fixture.public_bind.issuer_key_commitment,
        ),
        (
            "expected scope",
            fixture.public_bind.policy_commitment,
            fixture.public_bind.nullifier_scope + F::ONE,
            fixture.public_bind.issuer_key_commitment,
        ),
        (
            "expected issuer",
            fixture.public_bind.policy_commitment,
            fixture.public_bind.nullifier_scope,
            fixture.public_bind.issuer_key_commitment + F::ONE,
        ),
    ] {
        assert!(
            sealed::verify_sealed_receipt(
                &receipt,
                &pinned,
                &digest,
                TrustAnchor {
                    log_id: "test.log",
                    ed25519_public_key: &log_public_key,
                },
                policy,
                scope,
                issuer,
                &InMemoryReplaySet::new(),
            )
            .is_err(),
            "{name} mismatch was accepted"
        );
    }
}

#[test]
#[ignore = "real release-mode key generation"]
fn twice_setup_produces_the_same_verification_key_digest() {
    let fixture = Fixture::benchmark_deterministic(1, 1, 0, 0x5341525a4b).unwrap();
    let circuit = fixture.uniform_steps()[0].circuit.clone();
    let first_parameters = proofs::setup(&circuit).unwrap();
    let (_, first_vk) = Compressed::setup(&first_parameters).unwrap();
    let second_parameters = proofs::setup(&circuit).unwrap();
    let (_, second_vk) = Compressed::setup(&second_parameters).unwrap();
    assert_eq!(
        proofs::vk_digest(&first_vk).unwrap(),
        proofs::vk_digest(&second_vk).unwrap()
    );
}
