//! Profile-b Schnorr over Pallas (SAR-ZK §3.4).
//!
//! The proof field is Pallas `Fp`, but a Pallas point's scalar field is `Fq`
//! with order `q > p`. A signature scalar therefore travels through the
//! circuit as 255 explicit bits, never as an `Fp` field element that could
//! silently reduce a value in `[p, q)`.

use crate::{poseidon, E2, F};
use ff::{Field, PrimeField, PrimeFieldBits};
use halo2curves::{
    group::{Curve, Group},
    pasta::{Fq, Pallas, PallasAffine},
    CurveAffine,
};
use nova_snark::{
    frontend::{num::AllocatedNum, AllocatedBit, Boolean, ConstraintSystem, SynthesisError},
    gadgets::{ecc::AllocatedPoint, utils::alloc_num_equals},
};
use rand_core::{CryptoRng, RngCore};

/// Pallas's scalar field, whose modulus is the signature scalar order `q`.
pub type Scalar = Fq;
/// A Pallas scalar is represented in the circuit as exactly 255 little-endian bits.
pub const SCALAR_BITS: usize = 255;
pub type ScalarBits = [bool; SCALAR_BITS];

/// Affine Pallas point plus the one identity encoding used by this module.
///
/// Non-identity points use their literal `(x, y)` coordinates. The identity
/// has `(0, 0, true)` only for witness transport; it is rejected for both
/// issuer keys and Schnorr `R` values by verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PallasPoint {
    pub x: F,
    pub y: F,
    pub is_identity: bool,
}

/// A profile-b Schnorr signature `(R, s)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: PallasPoint,
    pub s: Scalar,
}

impl PallasPoint {
    /// The identity representation. It is useful for hostile tests, but never
    /// valid as an issuer key or signature `R`.
    pub fn identity() -> Self {
        Self {
            x: F::ZERO,
            y: F::ZERO,
            is_identity: true,
        }
    }

    /// Whether the point is a valid Pallas point (or the distinguished identity).
    pub fn is_on_curve(self) -> bool {
        self.to_curve().is_some()
    }

    fn to_curve(self) -> Option<Pallas> {
        if self.is_identity {
            return Some(Pallas::identity());
        }
        Option::<PallasAffine>::from(PallasAffine::from_xy(self.x, self.y)).map(Pallas::from)
    }

    fn from_curve(point: Pallas) -> Self {
        if bool::from(point.is_identity()) {
            return Self::identity();
        }
        let affine = point.to_affine();
        let coordinates: halo2curves::Coordinates<PallasAffine> =
            Option::from(affine.coordinates()).expect("non-identity has affine coordinates");
        Self {
            x: *coordinates.x(),
            y: *coordinates.y(),
            is_identity: false,
        }
    }
}

/// The mandated generator `G = (-1, 2)` on `y² = x³ + 5`.
pub fn generator() -> PallasPoint {
    PallasPoint {
        x: -F::ONE,
        y: F::from(2),
        is_identity: false,
    }
}

/// Sample a uniformly distributed nonzero Pallas scalar for a Schnorr secret
/// key. Callers retain it; [`public_key`] derives the corresponding key.
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    sample_nonzero_scalar(rng)
}

/// Compute `PK = sk·G`. Secret keys must be in `[1, q-1]`.
pub fn public_key(secret_key: Scalar) -> PallasPoint {
    assert!(
        !bool::from(secret_key.is_zero()),
        "Schnorr secret keys must be nonzero"
    );
    PallasPoint::from_curve(generator_curve() * secret_key)
}

/// Compute the profile's Fiat-Shamir challenge in the Pallas base field.
pub fn challenge(r: PallasPoint, public_key: PallasPoint, message: F) -> F {
    poseidon::hash_native(
        "SAR-ZK schnorr",
        &[r.x, r.y, public_key.x, public_key.y, message],
    )
}

/// Sign one field element with a uniformly sampled, unreused nonzero nonce.
pub fn sign<R: RngCore + CryptoRng>(secret_key: Scalar, message: F, rng: &mut R) -> Signature {
    sign_with_nonce(secret_key, sample_nonzero_scalar(rng), message)
}

/// Deterministic signing helper for fixtures. Production code should call
/// [`sign`], which samples its nonce itself. The caller is responsible for
/// ensuring `nonce` is uniformly random, nonzero, and never reused.
pub fn sign_with_nonce(secret_key: Scalar, nonce: Scalar, message: F) -> Signature {
    assert!(
        !bool::from(secret_key.is_zero()),
        "Schnorr secret keys must be nonzero"
    );
    assert!(
        !bool::from(nonce.is_zero()),
        "Schnorr nonces must be nonzero"
    );
    let public_key = public_key(secret_key);
    let r = PallasPoint::from_curve(generator_curve() * nonce);
    let c = challenge(r, public_key, message);
    Signature {
        r,
        s: nonce + fp_to_scalar(c) * secret_key,
    }
}

/// Native profile-b verification, including all strict input checks.
pub fn verify_native(public_key: PallasPoint, signature: Signature, message: F) -> bool {
    if public_key.is_identity
        || signature.r.is_identity
        || !public_key.is_on_curve()
        || !signature.r.is_on_curve()
    {
        return false;
    }

    let Some(public_key) = public_key.to_curve() else {
        return false;
    };
    let Some(r) = signature.r.to_curve() else {
        return false;
    };
    let c = fp_to_scalar(challenge(
        signature.r,
        PallasPoint::from_curve(public_key),
        message,
    ));
    generator_curve() * signature.s == r + public_key * c
}

/// Convert a canonical Pallas scalar into exactly 255 little-endian bits.
pub fn scalar_bits(scalar: Scalar) -> ScalarBits {
    field_bits_255(scalar)
}

/// Decode a scalar only if its 255-bit representation is canonical (`s < q`).
pub fn scalar_from_bits(bits: &ScalarBits) -> Option<Scalar> {
    if !scalar_bits_are_canonical(bits) {
        return None;
    }
    let mut scalar = Scalar::ZERO;
    let mut coefficient = Scalar::ONE;
    for bit in bits {
        if *bit {
            scalar += coefficient;
        }
        coefficient = coefficient.double();
    }
    Some(scalar)
}

/// Allocate canonical `Fq` scalar bits for a circuit witness.
pub fn alloc_scalar_bits<CS: ConstraintSystem<F>>(
    mut cs: CS,
    scalar: Scalar,
) -> Result<[AllocatedBit; SCALAR_BITS], SynthesisError> {
    alloc_scalar_bits_raw(cs.namespace(|| "scalar_bits"), &scalar_bits(scalar))
}

/// Allocate an arbitrary 255-bit scalar encoding. This is intentionally
/// exposed for hostile tests; [`verify_gadget`] enforces `s < q` itself.
pub fn alloc_scalar_bits_raw<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &ScalarBits,
) -> Result<[AllocatedBit; SCALAR_BITS], SynthesisError> {
    let mut allocated = Vec::with_capacity(SCALAR_BITS);
    for (index, bit) in bits.iter().copied().enumerate() {
        allocated.push(AllocatedBit::alloc(
            cs.namespace(|| format!("bit_{index}")),
            Some(bit),
        )?);
    }
    Ok(allocated
        .try_into()
        .expect("allocated exactly SCALAR_BITS scalar bits"))
}

/// Allocate a point witness for use with [`verify_gadget`]. The verifier
/// constrains curve membership and non-identity itself, so callers can use
/// this for adversarial fixtures too.
pub fn alloc_point<CS: ConstraintSystem<F>>(
    mut cs: CS,
    point: PallasPoint,
) -> Result<AllocatedPoint<E2>, SynthesisError> {
    AllocatedPoint::alloc(
        cs.namespace(|| "point"),
        Some((point.x, point.y, point.is_identity)),
    )
}

/// Verify profile-b Schnorr inside Nova's primary R1CS field (`Pallas Fp`).
///
/// Invalid curve points, identities, noncanonical `s`, and an invalid group
/// equation all create an unsatisfied constraint system rather than returning
/// a synthesis error. This matters because Nova setup fixes circuit shape and
/// callers must not accidentally treat an ignored synthesis error as a pass.
pub fn verify_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    public_key: &AllocatedPoint<E2>,
    r: &AllocatedPoint<E2>,
    supplied_s_bits: &[AllocatedBit; SCALAR_BITS],
    message: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let public_key = valid_nonidentity_point(cs.namespace(|| "public_key"), public_key)?;
    let r = valid_nonidentity_point(cs.namespace(|| "r"), r)?;

    let s_bits = supplied_s_bits.clone().map(Boolean::from);
    enforce_scalar_canonical(cs.namespace(|| "canonical_s"), &s_bits)?;

    let challenge = poseidon::hash_gadget(
        cs.namespace(|| "challenge"),
        "SAR-ZK schnorr",
        &[
            r.x.clone(),
            r.y.clone(),
            public_key.x.clone(),
            public_key.y.clone(),
            message.clone(),
        ],
    )?;
    // `to_bits_le_strict` binds the exact canonical integer in `[0, p)`, not
    // merely any 255-bit integer congruent to the challenge modulo `p`.
    let challenge_bits = challenge.to_bits_le_strict(cs.namespace(|| "canonical_challenge"))?;
    debug_assert_eq!(challenge_bits.len(), SCALAR_BITS);

    let generator = constant_generator(cs.namespace(|| "generator"))?;
    let lhs = scalar_mul_complete(cs.namespace(|| "lhs_s_times_g"), &generator, &s_bits)?;
    let rhs_mul = scalar_mul_complete(
        cs.namespace(|| "rhs_c_times_pk"),
        &public_key,
        &challenge_bits,
    )?;
    let rhs = r.add(cs.namespace(|| "rhs_r_plus_cpk"), &rhs_mul)?;
    lhs.enforce_equal(cs.namespace(|| "signature_equation"), &rhs)
}

fn generator_curve() -> Pallas {
    generator()
        .to_curve()
        .expect("the mandated (-1, 2) generator is a Pallas point")
}

/// Exact field-to-scalar embedding. The profile relies on `p < q`; this uses
/// a canonical representation conversion and fails loudly if that ever stops
/// being true, rather than reducing modulo `q`.
fn fp_to_scalar(value: F) -> Scalar {
    let repr = value.to_repr();
    Option::<Scalar>::from(Scalar::from_repr(repr))
        .expect("Pallas base field modulus p is strictly below scalar order q")
}

fn scalar_bits_are_canonical(bits: &ScalarBits) -> bool {
    let maximum = scalar_bits(-Scalar::ONE); // q - 1
    for index in (0..SCALAR_BITS).rev() {
        if bits[index] != maximum[index] {
            return !bits[index] && maximum[index];
        }
    }
    true
}

/// Enforce a 255-bit encoding `s <= q - 1` using a most-significant-bit
/// comparator. No conversion through `Fp` occurs, so `p <= s < q` remains
/// representable and valid.
fn enforce_scalar_canonical<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<(), SynthesisError> {
    debug_assert_eq!(bits.len(), SCALAR_BITS);
    let maximum = scalar_bits(-Scalar::ONE);
    let mut equal_prefix = Boolean::constant(true);
    let mut less = Boolean::constant(false);

    for index in (0..SCALAR_BITS).rev() {
        if maximum[index] {
            let candidate = Boolean::and::<F, _>(
                cs.namespace(|| format!("less_candidate_{index}")),
                &equal_prefix,
                &bits[index].not(),
            )?;
            less = Boolean::or::<F, _>(
                cs.namespace(|| format!("less_or_{index}")),
                &less,
                &candidate,
            )?;
            equal_prefix = Boolean::and::<F, _>(
                cs.namespace(|| format!("equal_one_{index}")),
                &equal_prefix,
                &bits[index],
            )?;
        } else {
            equal_prefix = Boolean::and::<F, _>(
                cs.namespace(|| format!("equal_zero_{index}")),
                &equal_prefix,
                &bits[index].not(),
            )?;
        }
    }
    let less_or_equal = Boolean::or::<F, _>(
        cs.namespace(|| "s_less_or_equal_q_minus_one"),
        &less,
        &equal_prefix,
    )?;
    Boolean::enforce_equal::<F, _>(
        cs.namespace(|| "s_less_than_q"),
        &less_or_equal,
        &Boolean::constant(true),
    )
}

/// Check the point's encoding is a bit, check its curve equation, require it
/// not to be infinity, and select an identity fallback for subsequent group
/// arithmetic if the supplied coordinates are malformed. The fallback keeps
/// the ECC gadget's internal inversions total; the independent validity
/// constraint still makes malformed witnesses unsatisfied.
fn valid_nonidentity_point<CS: ConstraintSystem<F>>(
    mut cs: CS,
    point: &AllocatedPoint<E2>,
) -> Result<AllocatedPoint<E2>, SynthesisError> {
    enforce_bit(cs.namespace(|| "infinity_is_bit"), &point.is_infinity);
    let infinity = Boolean::Is(AllocatedBit::from_parts_unchecked(
        point.is_infinity.get_variable(),
        point.is_infinity.get_value().map(|value| value == F::ONE),
    ));

    let y_square = point.y.square(cs.namespace(|| "y_square"))?;
    let x_square = point.x.square(cs.namespace(|| "x_square"))?;
    let x_cube = point.x.mul(cs.namespace(|| "x_cube"), &x_square)?;
    let rhs = add_constant(cs.namespace(|| "curve_rhs"), &x_cube, F::from(5))?;
    let equation = Boolean::from(alloc_num_equals(
        cs.namespace(|| "curve_equation"),
        &y_square,
        &rhs,
    )?);
    let affine_valid =
        Boolean::and::<F, _>(cs.namespace(|| "affine_valid"), &infinity.not(), &equation)?;
    let valid = Boolean::or::<F, _>(cs.namespace(|| "point_valid"), &infinity, &affine_valid)?;
    Boolean::enforce_equal::<F, _>(
        cs.namespace(|| "on_curve"),
        &valid,
        &Boolean::constant(true),
    )?;
    Boolean::enforce_equal::<F, _>(
        cs.namespace(|| "not_identity"),
        &infinity,
        &Boolean::constant(false),
    )?;

    let identity = AllocatedPoint::default(cs.namespace(|| "safe_identity"))?;
    AllocatedPoint::conditionally_select(
        cs.namespace(|| "safe_point"),
        point,
        &identity,
        &affine_valid,
    )
}

/// Complete, bit-by-bit double-and-add. We intentionally do not call Nova
/// 0.76's optimized `AllocatedPoint::scalar_mul`: it uses incomplete formulas
/// for most bits. This loop uses its public complete `add`, `double`, and
/// conditional-select gadgets for every bit, after `valid_nonidentity_point`
/// has made all inputs safe for their affine inversion witnesses.
fn scalar_mul_complete<CS: ConstraintSystem<F>>(
    mut cs: CS,
    point: &AllocatedPoint<E2>,
    bits: &[Boolean],
) -> Result<AllocatedPoint<E2>, SynthesisError> {
    let mut accumulator = AllocatedPoint::default(cs.namespace(|| "identity"))?;
    let mut base = point.clone();
    for (index, bit) in bits.iter().enumerate() {
        let added = accumulator.add(cs.namespace(|| format!("add_{index}")), &base)?;
        accumulator = AllocatedPoint::conditionally_select(
            cs.namespace(|| format!("select_{index}")),
            &added,
            &accumulator,
            bit,
        )?;
        if index + 1 != bits.len() {
            base = base.double(cs.namespace(|| format!("double_{index}")))?;
        }
    }
    Ok(accumulator)
}

fn constant_generator<CS: ConstraintSystem<F>>(
    mut cs: CS,
) -> Result<AllocatedPoint<E2>, SynthesisError> {
    let infinity = zero(cs.namespace(|| "infinity"))?;
    AllocatedPoint::alloc_constant(
        cs.namespace(|| "point"),
        (generator().x, generator().y),
        infinity,
    )
}

fn zero<CS: ConstraintSystem<F>>(mut cs: CS) -> Result<AllocatedNum<F>, SynthesisError> {
    let zero = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(F::ZERO))?;
    cs.enforce(|| "zero", |lc| lc, |lc| lc, |lc| lc + zero.get_variable());
    Ok(zero)
}

fn add_constant<CS: ConstraintSystem<F>>(
    mut cs: CS,
    input: &AllocatedNum<F>,
    constant: F,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "value"), || {
        Ok(input.get_value().ok_or(SynthesisError::AssignmentMissing)? + constant)
    })?;
    cs.enforce(
        || "add_constant",
        |lc| lc + input.get_variable() + (constant, CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

fn enforce_bit<CS: ConstraintSystem<F>>(mut cs: CS, value: &AllocatedNum<F>) {
    cs.enforce(
        || "bit",
        |lc| lc + value.get_variable(),
        |lc| lc + CS::one() - value.get_variable(),
        |lc| lc,
    );
}

fn field_bits_255<T: PrimeField + PrimeFieldBits>(value: T) -> ScalarBits {
    let bits = value.to_le_bits().into_iter().collect::<Vec<_>>();
    assert!(
        bits.len() >= SCALAR_BITS,
        "field representation is unexpectedly narrow"
    );
    assert!(
        bits[SCALAR_BITS..].iter().all(|bit| !*bit),
        "canonical Pasta field representation has a nonzero bit above 254"
    );
    bits[..SCALAR_BITS]
        .try_into()
        .expect("exactly 255 low bits were selected")
}

fn sample_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let candidate = Scalar::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::frontend::{test_cs::TestConstraintSystem, ConstraintSystem};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn fixture() -> (Scalar, Scalar, F, PallasPoint, Signature) {
        let secret = Scalar::from(7);
        let message = F::from(42);
        let public_key = public_key(secret);
        // Choose a deterministic honest signature whose integer `s + q`
        // still fits the 255-bit witness encoding. That lets the hostile test
        // isolate canonicality: `(s + q)·G = s·G` as a group equation.
        for nonce_u64 in 1..=64 {
            let nonce = Scalar::from(nonce_u64);
            let signature = sign_with_nonce(secret, nonce, message);
            if add_bits(scalar_bits(signature.s), scalar_modulus_bits()).is_some() {
                return (secret, nonce, message, public_key, signature);
            }
        }
        panic!("deterministic fixture did not find a 255-bit s + q");
    }

    fn verify_in_cs(
        public_key: PallasPoint,
        signature: Signature,
        message: F,
        bits: ScalarBits,
    ) -> TestConstraintSystem<F> {
        let mut cs = TestConstraintSystem::<F>::new();
        let public_key = alloc_point(cs.namespace(|| "pk"), public_key).unwrap();
        let r = alloc_point(cs.namespace(|| "r"), signature.r).unwrap();
        let s = alloc_scalar_bits_raw(cs.namespace(|| "s"), &bits).unwrap();
        let message = AllocatedNum::alloc(cs.namespace(|| "message"), || Ok(message)).unwrap();
        verify_gadget(cs.namespace(|| "verify"), &public_key, &r, &s, &message).unwrap();
        cs
    }

    #[test]
    fn native_signatures_verify_and_bind_message_and_key() {
        let (_, _, message, public_key, signature) = fixture();
        assert!(verify_native(public_key, signature, message));
        assert!(!verify_native(public_key, signature, message + F::ONE));
        assert!(!verify_native(
            super::public_key(Scalar::from(8)),
            signature,
            message
        ));
        assert!(!verify_native(
            public_key,
            Signature {
                r: PallasPoint::identity(),
                ..signature
            },
            message
        ));
    }

    #[test]
    fn safe_keygen_and_sign_api_produces_a_valid_signature() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0053_4348_4e4f_5252);
        let secret = keygen(&mut rng);
        let public_key = public_key(secret);
        let signature = sign(secret, F::from(123), &mut rng);
        assert!(verify_native(public_key, signature, F::from(123)));
    }

    #[test]
    fn scalar_bit_range_is_exactly_q_and_not_p() {
        let q_minus_one = scalar_bits(-Scalar::ONE);
        assert_eq!(scalar_from_bits(&q_minus_one), Some(-Scalar::ONE));

        let q = increment_bits(q_minus_one).expect("q fits in 255 bits");
        assert_eq!(scalar_from_bits(&q), None);

        let p_minus_one = scalar_bits_from_field_minus_one();
        let p = increment_bits(p_minus_one).expect("p fits in 255 bits");
        assert!(
            scalar_from_bits(&p).is_some(),
            "p < q must be accepted as a signature scalar"
        );

        let mut accepted = TestConstraintSystem::<F>::new();
        let q_minus_one =
            alloc_scalar_bits_raw(accepted.namespace(|| "q_minus_one"), &q_minus_one).unwrap();
        enforce_scalar_canonical(
            accepted.namespace(|| "check"),
            &q_minus_one.map(Boolean::from),
        )
        .unwrap();
        assert!(accepted.is_satisfied());

        let mut rejected = TestConstraintSystem::<F>::new();
        let q = alloc_scalar_bits_raw(rejected.namespace(|| "q"), &q).unwrap();
        enforce_scalar_canonical(rejected.namespace(|| "check"), &q.map(Boolean::from)).unwrap();
        assert!(!rejected.is_satisfied(), "q must be rejected, not reduced");

        let mut p_accepted = TestConstraintSystem::<F>::new();
        let p = alloc_scalar_bits_raw(p_accepted.namespace(|| "p"), &p).unwrap();
        enforce_scalar_canonical(p_accepted.namespace(|| "check"), &p.map(Boolean::from)).unwrap();
        assert!(p_accepted.is_satisfied(), "p < q must be accepted in R1CS");
    }

    #[test]
    fn circuit_signature_checks_and_hostile_cases_are_unsatisfied() {
        let (_, _, message, public_key, signature) = fixture();
        let valid = verify_in_cs(public_key, signature, message, scalar_bits(signature.s));
        eprintln!("Schnorr verifier constraints: {}", valid.num_constraints());
        assert!(
            valid.is_satisfied(),
            "valid signature: {:?}",
            valid.which_is_unsatisfied()
        );

        let wrong_message = verify_in_cs(
            public_key,
            signature,
            message + F::ONE,
            scalar_bits(signature.s),
        );
        assert!(!wrong_message.is_satisfied(), "wrong message GOT THROUGH");

        let wrong_key = verify_in_cs(
            super::public_key(Scalar::from(8)),
            signature,
            message,
            scalar_bits(signature.s),
        );
        assert!(!wrong_key.is_satisfied(), "wrong key GOT THROUGH");

        let s_plus_q = add_bits(scalar_bits(signature.s), scalar_modulus_bits())
            .expect("fixture selected a signature with 255-bit s + q");

        // Isolate the range check: q·G is the identity, so these two raw
        // 255-bit encodings produce the same group element before the
        // canonical-scalar comparator is applied.
        let mut periodicity = TestConstraintSystem::<F>::new();
        let generator = constant_generator(periodicity.namespace(|| "generator")).unwrap();
        let canonical_bits = alloc_scalar_bits_raw(
            periodicity.namespace(|| "canonical_s"),
            &scalar_bits(signature.s),
        )
        .unwrap()
        .map(Boolean::from);
        let noncanonical_bits =
            alloc_scalar_bits_raw(periodicity.namespace(|| "s_plus_q"), &s_plus_q)
                .unwrap()
                .map(Boolean::from);
        let canonical_multiple = scalar_mul_complete(
            periodicity.namespace(|| "canonical_multiple"),
            &generator,
            &canonical_bits,
        )
        .unwrap();
        let noncanonical_multiple = scalar_mul_complete(
            periodicity.namespace(|| "noncanonical_multiple"),
            &generator,
            &noncanonical_bits,
        )
        .unwrap();
        canonical_multiple
            .enforce_equal(
                periodicity.namespace(|| "same_group_element"),
                &noncanonical_multiple,
            )
            .unwrap();
        assert!(
            periodicity.is_satisfied(),
            "s + q must retain the same group multiple"
        );

        let noncanonical = verify_in_cs(public_key, signature, message, s_plus_q);
        assert!(!noncanonical.is_satisfied(), "s + q GOT THROUGH");

        let identity = verify_in_cs(
            public_key,
            Signature {
                r: PallasPoint::identity(),
                ..signature
            },
            message,
            scalar_bits(signature.s),
        );
        assert!(!identity.is_satisfied(), "identity R GOT THROUGH");

        let identity_pk = verify_in_cs(
            PallasPoint::identity(),
            signature,
            message,
            scalar_bits(signature.s),
        );
        assert!(
            !identity_pk.is_satisfied(),
            "identity public key GOT THROUGH"
        );

        let off_curve = verify_in_cs(
            PallasPoint {
                x: F::ZERO,
                y: F::ZERO,
                is_identity: false,
            },
            signature,
            message,
            scalar_bits(signature.s),
        );
        assert!(
            !off_curve.is_satisfied(),
            "off-curve public key GOT THROUGH"
        );
    }

    #[test]
    fn challenge_bits_use_the_canonical_pallas_base_encoding() {
        let mut cs = TestConstraintSystem::<F>::new();
        let challenge = AllocatedNum::alloc(cs.namespace(|| "challenge"), || Ok(-F::ONE)).unwrap();
        let bits = challenge
            .to_bits_le_strict(cs.namespace(|| "strict_bits"))
            .unwrap();
        assert_eq!(bits.len(), SCALAR_BITS);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn pallas_base_challenge_embedding_is_strictly_below_scalar_order() {
        let p_minus_one = -F::ONE;
        let embedded = fp_to_scalar(p_minus_one);
        assert_eq!(scalar_bits(embedded), field_bits_255(p_minus_one));
        assert!(
            scalar_from_bits(&increment_bits(field_bits_255(p_minus_one)).unwrap()).is_some(),
            "p must be below q, so p itself is a valid scalar"
        );
    }

    #[test]
    fn complete_scalar_multiplication_handles_zero_one_and_q_minus_one() {
        for scalar in [Scalar::ZERO, Scalar::ONE, -Scalar::ONE] {
            let mut cs = TestConstraintSystem::<F>::new();
            let point = alloc_point(cs.namespace(|| "point"), generator()).unwrap();
            let point = valid_nonidentity_point(cs.namespace(|| "valid"), &point).unwrap();
            let bits = alloc_scalar_bits(cs.namespace(|| "scalar"), scalar)
                .unwrap()
                .map(Boolean::from);
            let output = scalar_mul_complete(cs.namespace(|| "mul"), &point, &bits).unwrap();
            assert!(
                cs.is_satisfied(),
                "scalar edge failed: {:?}",
                cs.which_is_unsatisfied()
            );
            let got = PallasPoint {
                x: output.x.get_value().unwrap(),
                y: output.y.get_value().unwrap(),
                is_identity: output.is_infinity.get_value() == Some(F::ONE),
            };
            assert_eq!(got, PallasPoint::from_curve(generator_curve() * scalar));
        }
    }

    fn increment_bits(mut bits: ScalarBits) -> Option<ScalarBits> {
        for bit in &mut bits {
            if !*bit {
                *bit = true;
                return Some(bits);
            }
            *bit = false;
        }
        None
    }

    fn add_bits(mut left: ScalarBits, right: ScalarBits) -> Option<ScalarBits> {
        let mut carry = false;
        for index in 0..SCALAR_BITS {
            let a = left[index];
            let b = right[index];
            left[index] = a ^ b ^ carry;
            carry = (a & b) | (a & carry) | (b & carry);
        }
        (!carry).then_some(left)
    }

    fn scalar_modulus_bits() -> ScalarBits {
        increment_bits(scalar_bits(-Scalar::ONE)).expect("q fits in 255 bits")
    }

    fn scalar_bits_from_field_minus_one() -> ScalarBits {
        field_bits_255(-F::ONE)
    }
}
