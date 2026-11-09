//! `check` validates the receipt schema and optionally its signed log head.
//! `verify` additionally checks a real compressed proof and atomic replay state.

use std::process::ExitCode;
use zkar_prover::{
    proofs::{Compressed, CompressionVerifierKey, PinnedVerifierKey},
    relation::UniformCircuit,
    replay::FileReplaySet,
    sealed::{self, Outcome, TrustAnchor},
};

const USAGE: &str = "\
zkar — Sealed Agent Receipt tooling (SAR-ZK v0.4-draft)

USAGE:
  zkar check <sealed-receipt.json> [--trust <log-trust.json>]
      Validate schema and lexical forms. With --trust, also verify the
      Ed25519 log-head signature against the pinned public key.

  zkar verify <sealed-receipt.json> --vk <uniform-vk.bin> --vk-digest <hex>
      --trust <log-trust.json> --expected-policy <decimal>
      --expected-scope <decimal> --expected-issuer <decimal>
      --replay-file <replay.log>
      Fully verify a profile-b receipt and atomically record its nullifier.

  zkar keygen --out <dir>
      Generate uniform-vk.bin and uniform-vk.sha256 for the receipt circuit.

  zkar digest <file>
      Print the SHA-256 digest of the file in v0.2 `sha256:` DIGEST form.

  zkar fixtures <dir>
      Write deterministic schema/signature fixtures with an empty proof.

EXIT CODES:
  0  full sealed check passed
  1  check failed
  2  partial check passed: schema and log head signature; proof NOT verified
  3  schema only passed; nothing cryptographic was checked
  4  cryptographic checks passed, but replay was suspected
  64 bad command line
";

const PARTIAL: u8 = 2;
const SCHEMA_ONLY: u8 = 3;
const REPLAY_SUSPECTED: u8 = 4;
const USAGE_ERROR: u8 = 64;
// A maximum-size 64 KiB proof needs 87,382 base64url characters plus metadata.
const MAX_INPUT_BYTES: u64 = 128 * 1024;
// The serialized key contains the complete constraint shape, unlike a receipt.
const MAX_VK_BYTES: u64 = 128 * 1024 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("check") => cmd_check(&args),
        Some("verify") => cmd_verify(&args),
        Some("keygen") => cmd_keygen(&args),
        Some("digest") => cmd_digest(&args),
        Some("fixtures") => cmd_fixtures(&args),
        Some("help") | Some("--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(USAGE_ERROR)
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n\n{USAGE}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}

fn cmd_check(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(path) => path,
        None => {
            eprintln!("check requires a file argument");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    let mut trust_file = None;
    let mut index = 3;
    while index < args.len() {
        if args[index] != "--trust" {
            eprintln!("unexpected argument: {}", args[index]);
            return ExitCode::from(USAGE_ERROR);
        }
        if trust_file.is_some() {
            eprintln!("--trust given more than once");
            return ExitCode::from(USAGE_ERROR);
        }
        match args.get(index + 1) {
            Some(value) if !value.starts_with("--") => trust_file = Some(value),
            _ => {
                eprintln!("--trust requires a file argument");
                return ExitCode::from(USAGE_ERROR);
            }
        }
        index += 2;
    }

    let json = match read_text(path, MAX_INPUT_BYTES) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("SEALED CHECK FAILED: {error}");
            return ExitCode::FAILURE;
        }
    };
    let receipt = match zkar_core::statement::SealedReceipt::parse(&json) {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!("SEALED CHECK FAILED: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(path) = trust_file {
        match verify_trusted_head(&receipt, path) {
            Ok(()) => {
                println!(
                    "LOG HEAD SIGNATURE OK; PROOF NOT VERIFIED. This is not a sealed check pass."
                );
                ExitCode::from(PARTIAL)
            }
            Err(error) => {
                eprintln!("SEALED CHECK FAILED: {error}");
                ExitCode::FAILURE
            }
        }
    } else {
        println!("SCHEMA OK; NOTHING CRYPTOGRAPHIC CHECKED (pass --trust to check the log head signature). This is not a sealed check pass.");
        ExitCode::from(SCHEMA_ONLY)
    }
}

fn cmd_verify(args: &[String]) -> ExitCode {
    let Some(receipt_path) = args.get(2) else {
        eprintln!("verify requires a receipt file");
        return ExitCode::from(USAGE_ERROR);
    };
    const FLAGS: [&str; 7] = [
        "--vk",
        "--vk-digest",
        "--trust",
        "--expected-policy",
        "--expected-scope",
        "--expected-issuer",
        "--replay-file",
    ];
    let mut values: [Option<&str>; 7] = [None; 7];
    let mut index = 3;
    while index < args.len() {
        let Some(flag_index) = FLAGS.iter().position(|flag| *flag == args[index]) else {
            eprintln!("unexpected argument: {}", args[index]);
            return ExitCode::from(USAGE_ERROR);
        };
        if values[flag_index].is_some() {
            eprintln!("{} given more than once", args[index]);
            return ExitCode::from(USAGE_ERROR);
        }
        match args.get(index + 1) {
            Some(value) if !value.starts_with("--") => {
                values[flag_index] = Some(value);
            }
            _ => {
                eprintln!("{} requires an argument", args[index]);
                return ExitCode::from(USAGE_ERROR);
            }
        }
        index += 2;
    }
    let [Some(vk_path), Some(digest), Some(trust_path), Some(policy), Some(scope), Some(issuer), Some(replay_path)] =
        values
    else {
        eprintln!("verify requires --vk, --vk-digest, --trust, all expected commitments, and --replay-file");
        return ExitCode::from(USAGE_ERROR);
    };

    match verify_command(
        receipt_path,
        vk_path,
        digest,
        trust_path,
        policy,
        scope,
        issuer,
        replay_path,
    ) {
        Ok(Outcome::Passed) => {
            println!("SEALED CHECK PASSED");
            ExitCode::SUCCESS
        }
        Ok(Outcome::ReplaySuspected) => {
            eprintln!("SEALED CHECK REPLAY SUSPECTED");
            ExitCode::from(REPLAY_SUSPECTED)
        }
        Err(error) => {
            eprintln!("SEALED CHECK FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_command(
    receipt_path: &str,
    vk_path: &str,
    digest: &str,
    trust_path: &str,
    policy: &str,
    scope: &str,
    issuer: &str,
    replay_path: &str,
) -> Result<Outcome, String> {
    let json = read_text(receipt_path, MAX_INPUT_BYTES)?;
    let receipt = zkar_core::statement::SealedReceipt::parse(&json).map_err(|e| e.to_string())?;
    let pinned_digest = sealed::decode_digest(digest).map_err(|e| e.to_string())?;
    let vk_bytes = read_bytes(vk_path, MAX_VK_BYTES)?;
    let (raw_vk, consumed): (CompressionVerifierKey<UniformCircuit>, usize) =
        bincode::serde::decode_from_slice(&vk_bytes, bincode::config::legacy())
            .map_err(|e| format!("cannot decode verification key: {e}"))?;
    if consumed != vk_bytes.len() {
        return Err("verification key has trailing bytes".to_owned());
    }
    let pinned = PinnedVerifierKey::new(raw_vk, &pinned_digest).map_err(|e| e.to_string())?;
    let trust = load_trust(trust_path)?;
    let expected_policy = sealed::parse_field_decimal(policy).map_err(|e| e.to_string())?;
    let expected_scope = sealed::parse_field_decimal(scope).map_err(|e| e.to_string())?;
    let expected_issuer = sealed::parse_field_decimal(issuer).map_err(|e| e.to_string())?;
    let replay = FileReplaySet::new(replay_path).map_err(|e| e.to_string())?;
    sealed::verify_sealed_receipt(
        &receipt,
        &pinned,
        &pinned_digest,
        TrustAnchor {
            log_id: &trust.log_id,
            ed25519_public_key: &trust.public_key,
        },
        expected_policy,
        expected_scope,
        expected_issuer,
        &replay,
    )
    .map_err(|e| e.to_string())
}

fn cmd_keygen(args: &[String]) -> ExitCode {
    if args.len() != 4 || args[2] != "--out" || args[3].starts_with("--") {
        eprintln!("usage: zkar keygen --out <dir>");
        return ExitCode::from(USAGE_ERROR);
    }
    match write_verification_key(&args[3]) {
        Ok(digest) => {
            println!("verification-key digest: {digest}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("keygen failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn write_verification_key(dir: &str) -> Result<String, String> {
    use zkar_prover::{issuance::Fixture, proofs};

    let fixture = Fixture::benchmark_deterministic(1, 1, 0, 0x5341525a4b)
        .map_err(|error| error.to_string())?;
    let circuits: Vec<_> = fixture
        .uniform_steps()
        .into_iter()
        .map(|step| step.circuit)
        .collect();
    let parameters = proofs::setup(&circuits[0]).map_err(|error| error.to_string())?;
    let (_, vk) = Compressed::setup(&parameters).map_err(|error| error.to_string())?;
    let digest = proofs::vk_digest(&vk).map_err(|error| error.to_string())?;
    let bytes = proofs::encode(&vk).map_err(|error| error.to_string())?;
    let digest = sealed::digest_hex(&digest);
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    std::fs::write(format!("{dir}/uniform-vk.bin"), bytes).map_err(|error| error.to_string())?;
    std::fs::write(format!("{dir}/uniform-vk.sha256"), format!("{digest}\n"))
        .map_err(|error| error.to_string())?;
    Ok(digest)
}

struct TrustFile {
    log_id: String,
    public_key: [u8; 32],
}

fn load_trust(path: &str) -> Result<TrustFile, String> {
    let raw = read_text(path, MAX_INPUT_BYTES)?;
    let value = zkar_core::statement::parse_json_strict(&raw)
        .map_err(|error| format!("trust file is not valid JSON: {error}"))?;
    const MEMBERS: [&str; 3] = ["profile", "log_id", "ed25519_public_key_hex"];
    let object = value
        .as_object()
        .ok_or_else(|| "trust file must be a JSON object".to_owned())?;
    if let Some(member) = object.keys().find(|key| !MEMBERS.contains(&key.as_str())) {
        return Err(format!("trust file has unknown member `{member}`"));
    }
    let get = |member: &str| -> Result<&str, String> {
        object
            .get(member)
            .and_then(|value| value.as_str())
            .ok_or_else(|| format!("trust file must have a string `{member}` member"))
    };
    if get("profile")? != "sar-zk-log-trust-v0.4" {
        return Err("trust file profile must be `sar-zk-log-trust-v0.4`".to_owned());
    }
    let public_key = decode_hex(get("ed25519_public_key_hex")?)
        .map_err(|error| format!("ed25519_public_key_hex must be lowercase hex: {error}"))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "ed25519_public_key_hex must contain exactly 32 bytes".to_owned())?;
    Ok(TrustFile {
        log_id: get("log_id")?.to_owned(),
        public_key,
    })
}

fn verify_trusted_head(
    receipt: &zkar_core::statement::SealedReceipt,
    trust_path: &str,
) -> Result<(), String> {
    let trust = load_trust(trust_path)?;
    if trust.log_id != receipt.public_input.log_id {
        return Err("trust file is for a different log_id than the receipt".to_owned());
    }
    let signature = decode_b64url(&receipt.public_input.log_head_signature)
        .map_err(|error| format!("log_head_signature is not valid base64url: {error}"))?;
    let head = zkar_core::verify::canonical_head_bytes(&receipt.public_input)
        .map_err(|error| error.to_string())?;
    zkar_core::verify::verify_log_head_signature(&trust.public_key, &head, &signature)
        .map_err(|error| error.to_string())
}

fn read_text(path: &str, limit: u64) -> Result<String, String> {
    let bytes = read_bytes(path, limit)?;
    String::from_utf8(bytes).map_err(|error| format!("{path} is not UTF-8: {error}"))
}

fn read_bytes(path: &str, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {path}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{path} exceeds the {limit}-byte input limit"));
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex length".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("not lowercase hex".to_owned());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn decode_b64url(value: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut output = Vec::new();
    for byte in value.bytes() {
        let index = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("bad base64url character")?;
        accumulator = (accumulator << 6) | index as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    Ok(output)
}

fn cmd_digest(args: &[String]) -> ExitCode {
    let path = match args.get(2) {
        Some(path) => path,
        None => {
            eprintln!("digest requires a file argument");
            return ExitCode::FAILURE;
        }
    };
    match std::fs::read(path) {
        Ok(bytes) => {
            println!("{}", zkar_core::verify::sha256_digest(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_fixtures(args: &[String]) -> ExitCode {
    let dir = match args.get(2) {
        Some(dir) => dir,
        None => {
            eprintln!("fixtures requires a directory argument");
            return ExitCode::FAILURE;
        }
    };
    match write_fixtures(dir) {
        Ok(()) => {
            println!("wrote fixtures to {dir}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fixtures failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn write_fixtures(dir: &str) -> std::io::Result<()> {
    use ed25519_dalek::{Signer, SigningKey};

    std::fs::create_dir_all(dir)?;
    let mut seed = [0u8; 32];
    seed[0] = 0x5a;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let public_input = zkar_core::statement::PublicInput {
        profile: zkar_core::PROFILE_A.to_owned(),
        issuer_key_commitment: "1".to_owned(),
        log_root: "42".to_owned(),
        tree_size: "17".to_owned(),
        log_id: "log.1".to_owned(),
        log_head_signature: String::new(),
        policy_commitment: "7".to_owned(),
        nullifier_scope: "5".to_owned(),
        nullifier: "9".to_owned(),
    };
    let head = zkar_core::verify::canonical_head_bytes(&public_input)
        .expect("fixture head fields are short");
    let signature = base64url(&signing_key.sign(&head).to_bytes());
    let profile = zkar_core::PROFILE_A;
    let receipt = format!(
        "{{\"profile\":\"{profile}\",\"public_input\":{{\"profile\":\"{profile}\",\"issuer_key_commitment\":\"1\",\"log_root\":\"42\",\"tree_size\":\"17\",\"log_id\":\"log.1\",\"log_head_signature\":\"{signature}\",\"policy_commitment\":\"7\",\"nullifier_scope\":\"5\",\"nullifier\":\"9\"}},\"proof\":\"\",\"fold_count\":\"4\",\"algorithm\":{{\"arithmetization\":\"r1cs-nova-uniform\",\"curve\":\"pasta\",\"proof_encoding\":\"nova-snark-0.76.0/bincode-2.0.1-legacy\",\"vk_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}}}"
    );
    let trust = format!(
        "{{\"profile\":\"sar-zk-log-trust-v0.4\",\"log_id\":\"log.1\",\"ed25519_public_key_hex\":\"{}\"}}",
        hex(&verifying_key.to_bytes())
    );
    std::fs::write(format!("{dir}/sealed-receipt-0.json"), receipt)?;
    std::fs::write(format!("{dir}/log-trust.json"), trust)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
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

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures_verify_end_to_end() {
        let directory = std::env::temp_dir().join(format!("zkar-cli-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let dir = directory.to_str().unwrap();
        super::write_fixtures(dir).unwrap();
        let receipt = std::fs::read_to_string(format!("{dir}/sealed-receipt-0.json")).unwrap();
        let parsed = zkar_core::statement::SealedReceipt::parse(&receipt).unwrap();
        assert!(super::verify_trusted_head(&parsed, &format!("{dir}/log-trust.json")).is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
