use crate::{
    proofs::{self, Compressed, PinnedVerifierKey},
    relation::{PublicBind, UniformCircuit, PROFILE_B_TAG},
    replay::{self, ReplaySet},
    F,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ff::PrimeField;
use nova_snark::errors::NovaError;
use num_bigint::BigUint;
use zkar_core::{
    statement::{
        SealedReceipt, ARITHMETIZATION_NOVA_UNIFORM, ARITHMETIZATION_SUPERNOVA_RESERVED,
        CURVE_PASTA, PROOF_ENCODING_NOVA_BINCODE_LEGACY,
    },
    ZkarError, PROFILE_B,
};

pub const MAX_PROOF_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    ReplaySuspected,
}

#[derive(Debug)]
pub enum Error {
    Wire(ZkarError),
    Invalid(&'static str),
    ProofDecode(String),
    Proof(NovaError),
    Replay(replay::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(error) => write!(f, "invalid sealed receipt: {error}"),
            Self::Invalid(message) => f.write_str(message),
            Self::ProofDecode(message) => write!(f, "invalid proof encoding: {message}"),
            Self::Proof(error) => write!(f, "proof verification failed: {error}"),
            Self::Replay(error) => write!(f, "replay storage failed: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ZkarError> for Error {
    fn from(error: ZkarError) -> Self {
        Self::Wire(error)
    }
}

impl From<NovaError> for Error {
    fn from(error: NovaError) -> Self {
        Self::Proof(error)
    }
}

impl From<replay::Error> for Error {
    fn from(error: replay::Error) -> Self {
        Self::Replay(error)
    }
}

pub struct TrustAnchor<'a> {
    pub log_id: &'a str,
    pub ed25519_public_key: &'a [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn verify_sealed_receipt(
    receipt: &SealedReceipt,
    pinned: &PinnedVerifierKey<UniformCircuit>,
    pinned_vk_digest: &[u8; 32],
    trust: TrustAnchor<'_>,
    expected_policy_commitment: F,
    expected_nullifier_scope: F,
    expected_issuer_key_commitment: F,
    replay: &dyn ReplaySet,
) -> Result<Outcome, Error> {
    receipt.validate()?;
    if receipt.algorithm.arithmetization == ARITHMETIZATION_SUPERNOVA_RESERVED {
        return Err(Error::Invalid("SuperNova is reserved but not implemented"));
    }
    if receipt.algorithm.arithmetization != ARITHMETIZATION_NOVA_UNIFORM
        || receipt.algorithm.curve != CURVE_PASTA
        || receipt.algorithm.proof_encoding != PROOF_ENCODING_NOVA_BINCODE_LEGACY
    {
        return Err(Error::Invalid("unsupported receipt algorithm"));
    }
    if receipt.profile != PROFILE_B {
        return Err(Error::Invalid("full verification supports only profile b"));
    }

    let receipt_digest = decode_digest(&receipt.algorithm.vk_digest)?;
    if &receipt_digest != pinned_vk_digest || pinned.digest() != pinned_vk_digest {
        return Err(Error::Invalid(
            "receipt verification-key digest is not pinned",
        ));
    }

    let issuer_key_commitment = parse_field_decimal(&receipt.public_input.issuer_key_commitment)?;
    let log_root = parse_field_decimal(&receipt.public_input.log_root)?;
    let tree_size = parse_field_decimal(&receipt.public_input.tree_size)?;
    let policy_commitment = parse_field_decimal(&receipt.public_input.policy_commitment)?;
    let nullifier_scope = parse_field_decimal(&receipt.public_input.nullifier_scope)?;
    let nullifier = parse_field_decimal(&receipt.public_input.nullifier)?;
    let public_bind = PublicBind {
        profile_tag: F::from(PROFILE_B_TAG),
        issuer_key_commitment,
        log_root,
        tree_size,
        policy_commitment,
        nullifier_scope,
    };
    let fold_count = receipt
        .fold_count
        .parse::<usize>()
        .map_err(|_| Error::Invalid("invalid fold count"))?;
    let proof = decode_proof(&receipt.proof)?;

    if trust.log_id != receipt.public_input.log_id {
        return Err(Error::Invalid("trust anchor is for a different log"));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&receipt.public_input.log_head_signature)
        .map_err(|_| Error::Invalid("invalid log-head signature encoding"))?;
    if signature.len() != 64 {
        return Err(Error::Invalid("log-head signature must decode to 64 bytes"));
    }
    let head = zkar_core::verify::canonical_head_bytes(&receipt.public_input)?;
    zkar_core::verify::verify_log_head_signature(trust.ed25519_public_key, &head, &signature)?;
    proofs::verify(
        &proof,
        pinned,
        fold_count,
        &public_bind.to_array(),
        nullifier,
    )?;

    if policy_commitment != expected_policy_commitment {
        return Err(Error::Invalid("unexpected policy commitment"));
    }
    if nullifier_scope != expected_nullifier_scope {
        return Err(Error::Invalid("unexpected nullifier scope"));
    }
    if issuer_key_commitment != expected_issuer_key_commitment {
        return Err(Error::Invalid("unexpected issuer key commitment"));
    }

    if replay.check_and_insert(nullifier_scope, nullifier)? {
        Ok(Outcome::Passed)
    } else {
        Ok(Outcome::ReplaySuspected)
    }
}

pub fn encode_proof(
    proof: &Compressed<UniformCircuit>,
) -> Result<String, bincode::error::EncodeError> {
    proofs::encode(proof).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_proof(encoded: &str) -> Result<Compressed<UniformCircuit>, Error> {
    let max_encoded_len = (MAX_PROOF_BYTES * 8).div_ceil(6);
    if encoded.len() > max_encoded_len {
        return Err(Error::ProofDecode(format!(
            "decoded proof exceeds {MAX_PROOF_BYTES} bytes"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| Error::ProofDecode(error.to_string()))?;
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::ProofDecode(format!(
            "decoded proof exceeds {MAX_PROOF_BYTES} bytes"
        )));
    }
    let (proof, consumed) = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
        .map_err(|error| Error::ProofDecode(error.to_string()))?;
    if consumed != bytes.len() {
        return Err(Error::ProofDecode("trailing bytes after proof".to_owned()));
    }
    Ok(proof)
}

pub fn parse_field_decimal(value: &str) -> Result<F, Error> {
    if !zkar_core::lexical::is_pallas_field_decimal(value) {
        return Err(Error::Invalid(
            "field value is not canonical decimal below p",
        ));
    }
    let integer = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or(Error::Invalid("invalid canonical field decimal"))?;
    let mut bytes = integer.to_bytes_le();
    bytes.resize(32, 0);
    let mut repr = <F as PrimeField>::Repr::default();
    if repr.as_ref().len() != 32 {
        return Err(Error::Invalid("unexpected Pallas field representation"));
    }
    repr.as_mut().copy_from_slice(&bytes);
    let field: Option<F> = F::from_repr(repr).into();
    field.ok_or(Error::Invalid("field value is not canonical below p"))
}

pub fn field_decimal(value: F) -> String {
    BigUint::from_bytes_le(value.to_repr().as_ref()).to_str_radix(10)
}

pub fn decode_digest(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::Invalid(
            "verification-key digest must be lowercase hex",
        ));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Invalid("invalid verification-key digest"))?;
    }
    Ok(digest)
}

pub fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_decimals_never_reduce_modulo_p() {
        let maximum =
            "28948022309329048855892746252171976963363056481941560715954676764349967630336";
        let parsed = parse_field_decimal(maximum).unwrap();
        assert_eq!(field_decimal(parsed), maximum);
        assert!(parse_field_decimal(zkar_core::lexical::PALLAS_P_DECIMAL).is_err());
        assert!(parse_field_decimal("01").is_err());
    }

    #[test]
    fn proof_decoder_rejects_more_than_64_kib_before_bincode() {
        let oversized = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_PROOF_BYTES + 1]);
        assert!(matches!(
            decode_proof(&oversized),
            Err(Error::ProofDecode(message)) if message.contains("64") || message.contains("65536")
        ));
    }
}
