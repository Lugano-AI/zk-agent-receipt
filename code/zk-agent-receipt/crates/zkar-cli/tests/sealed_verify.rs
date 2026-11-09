use ed25519_dalek::{Signer, SigningKey};
use std::{path::Path, process::Command};
use zkar_core::statement::{
    Algorithm, PublicInput, SealedReceipt, ARITHMETIZATION_NOVA_UNIFORM, CURVE_PASTA,
    PROOF_ENCODING_NOVA_BINCODE_LEGACY,
};
use zkar_prover::{
    issuance::Fixture,
    proofs::{self, Compressed},
    sealed,
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[test]
#[ignore = "real release-mode proof and CLI processes"]
fn cli_keygen_full_verify_tamper_failures_and_replay_exit() {
    let directory = std::env::temp_dir().join(format!("zkar-cli-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let binary = env!("CARGO_BIN_EXE_zkar");
    let key_directory = directory.join("keys");
    let output = Command::new(binary)
        .args(["keygen", "--out", key_directory.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let digest = std::fs::read_to_string(key_directory.join("uniform-vk.sha256"))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(digest.len(), 64);

    let fixture = Fixture::benchmark_deterministic(1, 4, 2, 0x5341525a4b).unwrap();
    let circuits: Vec<_> = fixture
        .uniform_steps()
        .into_iter()
        .map(|step| step.circuit)
        .collect();
    let parameters = proofs::setup(&circuits[0]).unwrap();
    let (prover_key, _) = Compressed::setup(&parameters).unwrap();
    let presentation = fixture.present(&parameters, &prover_key).unwrap();
    assert!(proofs::encode(presentation.proof()).unwrap().len() <= sealed::MAX_PROOF_BYTES);
    let log_key = SigningKey::from_bytes(&[0x42; 32]);
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
    public_input.log_head_signature = base64url(&signature.to_bytes());
    let receipt = SealedReceipt {
        profile: zkar_core::PROFILE_B.to_owned(),
        public_input,
        proof: sealed::encode_proof(presentation.proof()).unwrap(),
        fold_count: presentation.fold_count().to_string(),
        algorithm: Algorithm {
            arithmetization: ARITHMETIZATION_NOVA_UNIFORM.to_owned(),
            curve: CURVE_PASTA.to_owned(),
            proof_encoding: PROOF_ENCODING_NOVA_BINCODE_LEGACY.to_owned(),
            vk_digest: digest.clone(),
        },
    };
    let receipt_json = serde_json::to_string(&receipt).unwrap();
    assert!(receipt_json.len() < 128 * 1024);
    let receipt_path = directory.join("receipt.json");
    std::fs::write(&receipt_path, receipt_json).unwrap();
    let trust_path = directory.join("trust.json");
    std::fs::write(
        &trust_path,
        format!(
            "{{\"profile\":\"sar-zk-log-trust-v0.4\",\"log_id\":\"test.log\",\"ed25519_public_key_hex\":\"{}\"}}",
            hex(&log_key.verifying_key().to_bytes())
        ),
    )
    .unwrap();
    let replay_path = directory.join("replay.log");

    let verify = |receipt_path: &Path, replay_path: &Path| {
        Command::new(binary)
            .arg("verify")
            .arg(receipt_path)
            .args([
                "--vk",
                key_directory.join("uniform-vk.bin").to_str().unwrap(),
            ])
            .args(["--vk-digest", &digest])
            .args(["--trust", trust_path.to_str().unwrap()])
            .args([
                "--expected-policy",
                &sealed::field_decimal(bind.policy_commitment),
            ])
            .args([
                "--expected-scope",
                &sealed::field_decimal(bind.nullifier_scope),
            ])
            .args([
                "--expected-issuer",
                &sealed::field_decimal(bind.issuer_key_commitment),
            ])
            .args(["--replay-file", replay_path.to_str().unwrap()])
            .output()
            .unwrap()
    };

    let passed = verify(&receipt_path, &replay_path);
    assert_eq!(
        passed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&passed.stdout),
        "SEALED CHECK PASSED\n"
    );
    let replayed = verify(&receipt_path, &replay_path);
    assert_eq!(replayed.status.code(), Some(4));

    let reject = |name: &str, candidate: SealedReceipt| {
        let path = directory.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_string(&candidate).unwrap()).unwrap();
        let replay = directory.join(format!("{name}.replay"));
        let output = verify(&path, &replay);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    let mut tampered = receipt.clone();
    tampered.proof.replace_range(
        0..1,
        if receipt.proof.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    reject("proof", tampered);
    tampered = receipt.clone();
    tampered.fold_count = "8".to_owned();
    reject("folds", tampered);
    tampered = receipt.clone();
    tampered.algorithm.vk_digest = "00".repeat(32);
    reject("digest", tampered);
    tampered = receipt.clone();
    tampered.public_input.log_head_signature.replace_range(
        0..1,
        if receipt.public_input.log_head_signature.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    reject("signature", tampered);

    std::fs::remove_dir_all(directory).unwrap();
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        output.push(ALPHABET[(value >> 18) as usize & 63] as char);
        output.push(ALPHABET[(value >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(value >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[value as usize & 63] as char);
        }
    }
    output
}
