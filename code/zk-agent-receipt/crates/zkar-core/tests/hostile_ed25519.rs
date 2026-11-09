//! attack2: Ed25519 strictness of verify_log_head_signature.
//! Each test prints what it tried; a "GOT THROUGH" assertion failure means the defence failed.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT as B, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use zkar_core::statement::PublicInput;
use zkar_core::verify::{canonical_head_bytes, verify_log_head_signature};

fn pi(tree_size: &str) -> PublicInput {
    PublicInput {
        profile: "sar-zk-v0.4a".into(),
        issuer_key_commitment: "1".into(),
        log_root: "42".into(),
        tree_size: tree_size.into(),
        log_id: "log.1".into(),
        log_head_signature: String::new(),
        policy_commitment: "7".into(),
        nullifier_scope: "5".into(),
        nullifier: "9".into(),
    }
}

/// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0);
    out
}

#[test]
fn small_order_keys_all_encodings_rejected() {
    let head = canonical_head_bytes(&pi("17")).unwrap();
    let sig = [0u8; 64];
    for (i, t) in EIGHT_TORSION.iter().enumerate() {
        let enc = t.compress().to_bytes();
        for sign in [0u8, 0x80] {
            let mut pk = enc;
            pk[31] = (pk[31] & 0x7f) | sign;
            let r = verify_log_head_signature(&pk, &head, &sig);
            assert!(r.is_err(), "torsion[{i}] sign {sign:#x} GOT THROUGH");
        }
    }
}

#[test]
fn non_canonical_y_encodings_rejected() {
    // y + p for y in 0..19 still fits in 255 bits: these are non-canonical encodings.
    let head = canonical_head_bytes(&pi("17")).unwrap();
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut decoded_noncanon = 0;
    for y in 0u8..19 {
        for sign in [0u8, 0x80] {
            let mut pk = p;
            pk[0] = pk[0].wrapping_add(y);
            pk[31] |= sign;
            let decodes = CompressedEdwardsY(pk).decompress().is_some();
            if decodes {
                decoded_noncanon += 1;
            }
            let r = verify_log_head_signature(&pk, &head, &[0u8; 64]);
            assert!(
                r.is_err(),
                "non-canonical y={y}+p sign={sign:#x} GOT THROUGH"
            );
            if decodes {
                eprintln!(
                    "y={y}+p sign={sign:#x}: dalek decodes it; ours says {:?}",
                    r.unwrap_err()
                );
            }
        }
    }
    eprintln!("non-canonical encodings dalek accepted at decode: {decoded_noncanon}");
}

#[test]
fn non_canonical_s_rejected() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let head = canonical_head_bytes(&pi("17")).unwrap();
    let sig = sk.sign(&head).to_bytes();
    assert!(verify_log_head_signature(&sk.verifying_key().to_bytes(), &head, &sig).is_ok());
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    let s_plus_l = add_le(&s, &L);
    let mut bad = sig;
    bad[32..].copy_from_slice(&s_plus_l);
    let r = verify_log_head_signature(&sk.verifying_key().to_bytes(), &head, &bad);
    eprintln!("s+L: {r:?}");
    assert!(r.is_err(), "s + L GOT THROUGH");
    let mut hi = sig;
    hi[63] |= 0x80;
    assert!(
        verify_log_head_signature(&sk.verifying_key().to_bytes(), &head, &hi).is_err(),
        "high-bit s GOT THROUGH"
    );
}

fn k_hash(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(m);
    let d: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&d)
}

/// Mixed-order key A = a·B + T (T of order 8). Not small order, canonically encoded,
/// so the checker accepts the key. Build a signature whose R is a torsion point and
/// that satisfies the cofactorless equation; verify_strict must still refuse it.
#[test]
fn small_order_r_under_mixed_order_key_rejected() {
    let a = Scalar::from_bytes_mod_order([9u8; 32]);
    let t = EIGHT_TORSION[1];
    let big_a: EdwardsPoint = B * a + t;
    let a_bytes = big_a.compress().to_bytes();
    assert!(!big_a.is_small_order());
    assert!(!big_a.is_torsion_free());
    let mut found = false;
    'outer: for ts in 1u32..400 {
        let head = canonical_head_bytes(&pi(&ts.to_string())).unwrap();
        for rt in EIGHT_TORSION.iter() {
            let r_bytes = rt.compress().to_bytes();
            let k = k_hash(&r_bytes, &a_bytes, &head);
            // need R + k·A == s·B with s = k·a  <=>  R + k·T == identity
            if (rt + t * k).is_identity_check() {
                let s = k * a;
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&r_bytes);
                sig[32..].copy_from_slice(&s.to_bytes());
                // Sanity: the cofactorless equation holds.
                assert_eq!(B * s, rt + big_a * k);
                let r = verify_log_head_signature(&a_bytes, &head, &sig);
                eprintln!(
                    "tree_size={ts}: torsion R with mixed key, cofactorless eq holds; ours: {r:?}"
                );
                assert!(r.is_err(), "small-order R GOT THROUGH");
                // Show the strict check is load-bearing: non-strict verify accepts it.
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&a_bytes).unwrap();
                let lax = ed25519_dalek::Verifier::verify(
                    &vk,
                    &head,
                    &ed25519_dalek::Signature::from_bytes(&sig),
                );
                eprintln!("non-strict verify on the same input: {lax:?}");
                found = true;
                break 'outer;
            }
        }
    }
    assert!(found, "could not build the instance");
}

/// Mixed-order key, honest-style signatures: cofactored verifiers accept every one,
/// cofactorless (ours) accepts only those with k ≡ 0 (mod 8). This shows that a log
/// key with a torsion component is accepted by the key check, so a log can sign heads
/// that RFC 8032 cofactored verifiers accept and this verifier refuses.
#[test]
fn mixed_order_log_key_is_rejected() {
    let a = Scalar::from_bytes_mod_order([9u8; 32]);
    let t = EIGHT_TORSION[1];
    let big_a: EdwardsPoint = B * a + t;
    let a_bytes = big_a.compress().to_bytes();
    let (mut ours_ok, mut cofactored_ok) = (0, 0);
    let n = 64;
    for ts in 1u32..=n {
        let head = canonical_head_bytes(&pi(&ts.to_string())).unwrap();
        let r_scalar = Scalar::from_bytes_mod_order([ts as u8; 32]);
        let r_pt = B * r_scalar;
        let r_bytes = r_pt.compress().to_bytes();
        let k = k_hash(&r_bytes, &a_bytes, &head);
        let s = r_scalar + k * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s.to_bytes());
        // cofactored: [8](sB - R - kA) == 0
        if (B * s - r_pt - big_a * k)
            .mul_by_cofactor()
            .is_identity_check()
        {
            cofactored_ok += 1;
        }
        if verify_log_head_signature(&a_bytes, &head, &sig).is_ok() {
            ours_ok += 1;
        }
    }
    eprintln!(
        "mixed-order key: cofactored accepts {cofactored_ok}/{n}, ours accepts {ours_ok}/{n}"
    );
    assert_eq!(cofactored_ok, n);
    assert_eq!(ours_ok, 0, "GOT THROUGH: mixed-order (torsion-component) log key accepted; verifiers split {ours_ok}/{cofactored_ok}");
}

trait IdCheck {
    fn is_identity_check(&self) -> bool;
}
impl IdCheck for EdwardsPoint {
    fn is_identity_check(&self) -> bool {
        self.compress()
            == CompressedEdwardsY([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
    }
}

#[test]
fn wrong_lengths_rejected() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let head = canonical_head_bytes(&pi("17")).unwrap();
    let sig = sk.sign(&head).to_bytes();
    assert!(verify_log_head_signature(&sk.verifying_key().to_bytes()[..31], &head, &sig).is_err());
    assert!(verify_log_head_signature(&sk.verifying_key().to_bytes(), &head, &sig[..63]).is_err());
    let mut long = sig.to_vec();
    long.push(0);
    assert!(verify_log_head_signature(&sk.verifying_key().to_bytes(), &head, &long).is_err());
}

/// canonical_head_bytes claims injectivity "for any field contents, valid or not",
/// but a field longer than 65535 bytes panics instead.
#[test]
fn head_bytes_panic_on_long_unvalidated_field() {
    let mut p = pi("17");
    p.log_id = "a".repeat(70_000);
    let r = std::panic::catch_unwind(|| canonical_head_bytes(&p).is_err());
    eprintln!("70,000-byte log_id: panicked = {}", r.is_err());
    assert!(
        matches!(r, Ok(true)),
        "GOT THROUGH: canonical_head_bytes panicked or framed an unframeable field"
    );
}
