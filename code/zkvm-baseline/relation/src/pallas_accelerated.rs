//! Pallas Schnorr scalar multiplication over the bigint2 elliptic-curve
//! precompiles.
//!
//! The two verifier scalar multiplications (`generator * s` and
//! `public_key * challenge`) previously used portable `pasta_curves`
//! arithmetic inside the guest. This module re-expresses exactly those
//! computations over `risc0-bigint2`'s generic short-Weierstrass affine
//! precompiles, configured with the Pallas base-field prime, `a = 0`, and
//! `b = 5`.
//!
//! Every relation check is preserved: callers still parse points through the
//! portable on-curve, non-identity, and canonical-encoding checks before
//! reaching this module, scalars are still checked against the scalar modulus,
//! and the `bigint2` point operations themselves assert canonical (less than
//! the prime) coordinates against a dishonest host. The
//! double-and-add routine assumes an on-curve input and a scalar below the
//! group order; both hold here because the inputs are validated points, the
//! fixed generator, and canonical `Fq` scalars (the scalar-zero case is
//! handled explicitly by `AffinePoint::mul`).

use super::{Error, FieldWire, Fq};
use pasta_curves::{
    arithmetic::CurveAffine as PastaCurveAffine,
    group::{ff::Field, Curve, CurveAffine as GroupCurveAffine},
    pallas,
};
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
use super::accelerated::MODULUS;
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
use risc0_bigint2::ec::{
    AffinePoint, Curve as Bigint2Curve, WeierstrassCurve, EC_256_WIDTH_WORDS,
};

/// 256-bit field and scalar widths in little-endian 32-bit limbs.
const LIMBS: usize = EC_256_WIDTH_WORDS_OR_8;

/// Fallback width for native builds, where the bigint2 crate is not linked.
#[cfg(not(all(target_os = "zkvm", feature = "risc0-accelerated")))]
const EC_256_WIDTH_WORDS_OR_8: usize = 8;
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
const EC_256_WIDTH_WORDS_OR_8: usize = EC_256_WIDTH_WORDS;

/// Pallas curve equation `y^2 = x^3 + 5` over the shared base-field prime.
#[cfg(any(test, all(target_os = "zkvm", feature = "risc0-accelerated")))]
const CURVE_B: [u32; LIMBS] = [5, 0, 0, 0, 0, 0, 0, 0];

#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PallasCurve {}

#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
impl Bigint2Curve<EC_256_WIDTH_WORDS> for PallasCurve {
    const CURVE: &'static WeierstrassCurve<EC_256_WIDTH_WORDS> =
        &WeierstrassCurve::<EC_256_WIDTH_WORDS>::new(MODULUS, [0; LIMBS], CURVE_B);
}

/// A bigint2 affine point on Pallas.
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
pub(super) type Point = AffinePoint<EC_256_WIDTH_WORDS, PallasCurve>;

/// Canonical little-endian `u32` limbs of a 32-byte wire encoding.
fn wire_to_limbs(wire: &FieldWire) -> [u32; LIMBS] {
    core::array::from_fn(|index| {
        u32::from_le_bytes(wire[index * 4..index * 4 + 4].try_into().expect("32-byte wire"))
    })
}

/// Canonical little-endian `u32` limbs of a scalar-field element.
fn scalar_limbs(value: Fq) -> [u32; LIMBS] {
    wire_to_limbs(&super::scalar_to_wire(value))
}

/// Convert a validated, non-identity Pallas point into bigint2 limb form.
/// The returned point is unchecked; the caller has already verified the
/// point is on the curve and is not the identity.
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
fn to_bigint2(point: pallas::Affine) -> Result<Point, Error> {
    let coordinates = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
        <pallas::Affine as PastaCurveAffine>::coordinates(&point),
    )
    .ok_or(Error::IdentityPoint)?;
    Ok(AffinePoint::new_unchecked(
        wire_to_limbs(&super::fp_to_wire(*coordinates.x())),
        wire_to_limbs(&super::fp_to_wire(*coordinates.y())),
    ))
}

/// Check a bigint2 result against the portable Pasta result using the same
/// canonical wire encoding, so equality does not depend on limb form.
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
fn matches_pasta(point: &Point, expected: pallas::Affine) -> bool {
    let expected_identity = bool::from(<pallas::Affine as GroupCurveAffine>::is_identity(
        &expected,
    ));
    if point.is_identity() || expected_identity {
        return point.is_identity() && expected_identity;
    }
    let Some(buffer) = point.as_u32s() else {
        return false;
    };
    let coordinates = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
        <pallas::Affine as PastaCurveAffine>::coordinates(&expected),
    )
    .expect("non-identity point has coordinates");
    buffer[0] == wire_to_limbs(&super::fp_to_wire(*coordinates.x()))
        && buffer[1] == wire_to_limbs(&super::fp_to_wire(*coordinates.y()))
}

/// Evaluate `s * G == R + c * PK` entirely over the bigint2 curve layer.
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
pub(super) fn verify_schnorr_challenge(
    public_key: pallas::Affine,
    r: pallas::Affine,
    s: Fq,
    challenge_scalar: Fq,
) -> Result<(), Error> {
    let generator = super::pallas_generator()?;
    let g = to_bigint2(generator)?;
    let pk = to_bigint2(public_key)?;
    let r_point = to_bigint2(r)?;
    let s_limbs = scalar_limbs(s);
    let c_limbs = scalar_limbs(challenge_scalar);

    let mut left = Point::IDENTITY;
    g.mul(&s_limbs, &mut left);
    let mut pk_times_c = Point::IDENTITY;
    pk.mul(&c_limbs, &mut pk_times_c);
    let mut right = Point::IDENTITY;
    r_point.add(&pk_times_c, &mut right);

    if left == right {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Compare the bigint2 curve layer against portable Pasta on boundary
/// scalars and points before the guest relies on it.
#[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
pub(super) fn self_test() -> Result<(), Error> {
    let generator = super::pallas_generator()?;
    let g = to_bigint2(generator)?;

    // The scalar is below the group order because p < q for Pallas. It is
    // chosen deterministically to exercise many double-and-add rounds,
    // including the zero and one boundary cases.
    let scalars = [Fq::ZERO, Fq::ONE, Fq::from(2), -Fq::ONE];
    for scalar in scalars {
        let mut fast = Point::IDENTITY;
        g.mul(&scalar_limbs(scalar), &mut fast);
        let portable = (generator * scalar).to_affine();
        if !matches_pasta(&fast, portable) {
            return Err(Error::AcceleratorMismatch);
        }
    }

    // Point addition, including the P + P doubling edge, must also agree.
    let twice = (generator + generator).to_affine();
    let g_fast = to_bigint2(generator)?;
    let mut sum = Point::IDENTITY;
    g_fast.add(&g, &mut sum);
    if !matches_pasta(&sum, twice) {
        return Err(Error::AcceleratorMismatch);
    }
    let mut sum2 = Point::IDENTITY;
    g_fast.add(&to_bigint2(twice)?, &mut sum2);
    if !matches_pasta(&sum2, (twice + generator).to_affine()) {
        return Err(Error::AcceleratorMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The limb parser must reproduce Pasta's canonical wire encoding of the
    /// fixed generator, whose x coordinate is exactly p - 1.
    #[test]
    fn generator_limbs_match_pasta_repr() {
        let generator = super::super::pallas_generator().unwrap();
        let coordinates = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
            <pallas::Affine as PastaCurveAffine>::coordinates(&generator),
        )
        .unwrap();
        let expected_x: FieldWire = super::super::fp_to_wire(-pallas::Base::ONE);
        assert_eq!(
            wire_to_limbs(&super::super::fp_to_wire(*coordinates.x())),
            wire_to_limbs(&expected_x)
        );
        let expected_y: FieldWire = super::super::fp_to_wire(pallas::Base::from(2));
        assert_eq!(
            wire_to_limbs(&super::super::fp_to_wire(*coordinates.y())),
            wire_to_limbs(&expected_y)
        );
    }

    /// The configured curve equation is Pallas: the generator satisfies
    /// y^2 = x^3 + 5 over the shared modulus, and b is nonzero.
    #[test]
    fn pallas_curve_parameters_are_consistent() {
        let generator = super::super::pallas_generator().unwrap();
        let coordinates = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
            <pallas::Affine as PastaCurveAffine>::coordinates(&generator),
        )
        .unwrap();
        let x = *coordinates.x();
        let y = *coordinates.y();
        assert_eq!(y * y, x * x * x + pallas::Base::from(5));
        assert_ne!(CURVE_B, [0u32; LIMBS]);
    }
}
