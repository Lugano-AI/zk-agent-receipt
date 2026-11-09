//! Real cryptographic checks that back the sealed-receipt wire format.
//!
//! This is the non-zero-knowledge, verifier-facing path: Ed25519 verification
//! of the signed log head and SHA-256 digest computation. The zero-knowledge
//! folding proof is implemented separately in `zkar-prover`. Everything here
//! compiles, runs, and is tested against
//! real keys and real hashes.

use crate::statement::PublicInput;
use crate::ZkarError;
use sha2::{Digest, Sha256};

/// The head bytes the log signer signs (SAR-ZK §7.1):
/// `"SAR-ZK-head-v0.4" || 0x00 || frame(profile) || frame(hash_suite) ||
/// frame(log_id) || frame(log_root) || frame(tree_size)`, where `frame(x)` is
/// a 2-byte big-endian length followed by `x`'s ASCII wire form. The length
/// framing makes the encoding injective for any field contents. A field longer
/// than 65,535 bytes cannot be framed and is an error.
pub fn canonical_head_bytes(pi: &PublicInput) -> Result<Vec<u8>, ZkarError> {
    let mut b = Vec::with_capacity(192);
    b.extend_from_slice(b"SAR-ZK-head-v0.4\x00");
    for field in [
        pi.profile.as_str(),
        crate::HASH_SUITE,
        pi.log_id.as_str(),
        pi.log_root.as_str(),
        pi.tree_size.as_str(),
    ] {
        let len = u16::try_from(field.len())
            .map_err(|_| ZkarError::Other("log head field is longer than 65,535 bytes"))?;
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(field.as_bytes());
    }
    Ok(b)
}

/// Verify an Ed25519 signature over the head bytes.
///
/// Verification is strict (spec §3.4): small-order, non-canonical and
/// mixed-order (torsion) public keys are rejected, and `verify_strict` rejects small-order `R` and
/// non-canonical `s`.
///
/// The public key is caller-supplied (out of band, v0.2 §2 discipline — the
/// receipt never carries a usable key). `pk` is 32 bytes; `sig` is 64 bytes.
pub fn verify_log_head_signature(
    pk: &[u8],
    head_bytes: &[u8],
    sig: &[u8],
) -> Result<(), ZkarError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk: [u8; 32] = pk
        .try_into()
        .map_err(|_| ZkarError::Other("log public key must be exactly 32 bytes"))?;
    let sig_bytes: [u8; 64] = sig
        .try_into()
        .map_err(|_| ZkarError::Other("log head signature must be exactly 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&vk)
        .map_err(|_| ZkarError::Other("log public key is not a valid Ed25519 point"))?;
    if verifying_key.is_weak() {
        return Err(ZkarError::Other("log public key has small order"));
    }
    // A key with a small-order component would let cofactored and cofactorless
    // verifiers disagree about the same head, splitting gossiping verifiers.
    if !verifying_key.to_edwards().is_torsion_free() {
        return Err(ZkarError::Other("log public key has a torsion component"));
    }
    if VerifyingKey::from(verifying_key.to_edwards()).to_bytes() != vk {
        return Err(ZkarError::Other(
            "log public key is not canonically encoded",
        ));
    }
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(head_bytes, &signature)
        .map_err(|_| ZkarError::Other("log head signature verification failed"))
}

/// SHA-256 digest in the v0.2 `DIGEST` lexical form: `sha256:` + 64 lowercase
/// hex characters. This is the hash every inventory entry carries.
pub fn sha256_digest(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for byte in d {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::PublicInput;

    fn test_public_input(root: &str, tree_size: &str) -> PublicInput {
        PublicInput {
            profile: crate::PROFILE_A.to_string(),
            issuer_key_commitment: "1".to_string(),
            log_root: root.to_string(),
            tree_size: tree_size.to_string(),
            log_id: "log.1".to_string(),
            log_head_signature: String::new(), // filled after signing
            policy_commitment: "7".to_string(),
            nullifier_scope: "5".to_string(),
            nullifier: "9".to_string(),
        }
    }

    #[test]
    fn ed25519_head_signature_verifies_and_rejects_tampering() {
        use ed25519_dalek::{Signer, SigningKey};

        // Deterministic synthetic key: fixed seed, no RNG dependency.
        let mut seed = [0u8; 32];
        seed[0] = 0x5a;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut pi = test_public_input("42", "17");
        let head = canonical_head_bytes(&pi).unwrap();
        let sig: ed25519_dalek::Signature = signing_key.sign(&head);
        pi.log_head_signature = base64url(sig.to_bytes().as_ref());

        // Real check passes.
        assert!(
            verify_log_head_signature(&verifying_key.to_bytes(), &head, &sig.to_bytes()).is_ok()
        );

        // Flip one head byte: must fail.
        let mut bad_head = head.clone();
        bad_head[0] ^= 1;
        assert!(
            verify_log_head_signature(&verifying_key.to_bytes(), &bad_head, &sig.to_bytes())
                .is_err()
        );

        // Wrong key: must fail.
        let mut other_seed = [0u8; 32];
        other_seed[0] = 0x6b;
        let other = SigningKey::from_bytes(&other_seed);
        assert!(verify_log_head_signature(
            &other.verifying_key().to_bytes(),
            &head,
            &sig.to_bytes()
        )
        .is_err());
    }

    /// Minimal unpadded base64url encoder, used only by tests to place a real
    /// signature into the wire format. The on-wire decoder is `lexical::is_b64url`.
    fn base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 63] as char);
            }
        }
        out
    }

    #[test]
    fn sha256_digest_form_matches_v02_lexical_form() {
        assert_eq!(
            sha256_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(crate::lexical::is_digest(&sha256_digest(b"abc")));
    }

    #[test]
    fn head_framing_separates_fields_that_nul_separators_would_merge() {
        // Without length framing, ("a\x00b", "1") and ("a", "b\x001") could give
        // the same bytes. Framing must keep them apart even for unvalidated input.
        let mut x = test_public_input("1", "17");
        x.log_id = "a\x00b".to_string();
        let mut y = test_public_input("b\x001", "17");
        y.log_id = "a".to_string();
        assert_ne!(
            canonical_head_bytes(&x).unwrap(),
            canonical_head_bytes(&y).unwrap()
        );
    }

    #[test]
    fn oversized_head_field_is_an_error_not_a_panic() {
        let mut pi = test_public_input("42", "17");
        pi.log_id = "a".repeat(70_000);
        assert!(canonical_head_bytes(&pi).is_err());
    }

    #[test]
    fn head_bytes_bind_the_hash_suite() {
        let pi = test_public_input("42", "17");
        let b = canonical_head_bytes(&pi).unwrap();
        let suite = crate::HASH_SUITE.as_bytes();
        assert!(b.windows(suite.len()).any(|w| w == suite));
    }

    #[test]
    fn identity_key_forgery_is_rejected() {
        // The identity point (y = 1) with R = identity, s = 0 verifies every
        // message under cofactorless `verify`; strict checking must refuse it.
        let mut pk = [0u8; 32];
        pk[0] = 1;
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let head = canonical_head_bytes(&test_public_input("42", "17")).unwrap();
        assert!(verify_log_head_signature(&pk, &head, &sig).is_err());
    }

    #[test]
    fn canonical_head_bytes_are_length_tight_and_deterministic() {
        let pi = test_public_input("42", "17");
        let a = canonical_head_bytes(&pi).unwrap();
        let b = canonical_head_bytes(&pi).unwrap();
        assert_eq!(a, b);
        // Different tree size must produce different signed bytes.
        let mut other = test_public_input("42", "18");
        let c = canonical_head_bytes(&other).unwrap();
        assert_ne!(a, c);
        other.tree_size = "18".to_string();
        assert_eq!(c, canonical_head_bytes(&other).unwrap());
    }
}
