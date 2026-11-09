//! The SAR-ZK Poseidon construction (profile §3.2).
//!
//! Orchard's released `halo2_poseidon` 0.2.0 implementation uses Pasta 0.6
//! and `ff` 0.14, while Nova 0.76 uses `halo2curves` 0.9 and `ff` 0.13. The
//! two field types below have the same modulus and canonical little-endian
//! representation. We import the Orchard round constants once, convert those
//! canonical representations, and independently implement the native and
//! Nova-R1CS permutations over Nova's primary field (`Pallas Fp`).

use crate::F;
use ff::{Field as Field13, PrimeField as PrimeField13};
use ff14::PrimeField as PrimeField14;
use halo2_poseidon::{Mds, P128Pow5T3, Spec};
use nova_snark::frontend::{
    num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use pasta_curves::pallas::Base as OrchardFp;
use std::sync::OnceLock;

/// Width and rate required by SAR-ZK §3.2.
pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

#[derive(Clone)]
struct Constants {
    round_constants: [[F; WIDTH]; ROUNDS],
    mds: [[F; WIDTH]; WIDTH],
}

static CONSTANTS: OnceLock<Constants> = OnceLock::new();

/// Return the big-endian integer represented by an ASCII domain label.
///
/// The profile caps labels at 31 bytes, so their integer encoding is always
/// canonical in Pallas `Fp`.
pub fn domain_tag(domain: &str) -> F {
    assert!(domain.is_ascii(), "Poseidon domain labels must be ASCII");
    assert!(
        domain.len() <= 31,
        "Poseidon domain labels are at most 31 bytes"
    );

    domain.bytes().fold(F::ZERO, |tag, byte| {
        tag * F::from(256u64) + F::from(byte as u64)
    })
}

/// The exact Orchard P128Pow5T3 permutation over Pallas `Fp`.
///
/// This independently follows the released `halo2_poseidon` round order:
/// four full rounds, 56 partial rounds, then four full rounds.
pub fn permutation_native(mut state: [F; WIDTH]) -> [F; WIDTH] {
    let constants = constants();
    for (round, round_constants) in constants.round_constants.iter().enumerate() {
        let partial = is_partial_round(round);
        for word in 0..WIDTH {
            state[word] += round_constants[word];
            if !partial || word == 0 {
                state[word] = pow5_native(state[word]);
            }
        }
        state = apply_mds_native(&state, &constants.mds);
    }
    state
}

/// `H_D(x_1, ..., x_k)` from SAR-ZK §3.2.
///
/// The first absorbed pair is always `(tag(D), k)` and every pair, including
/// the final zero-padded one, is followed by a permutation.
pub fn hash_native(domain: &str, inputs: &[F]) -> F {
    assert!(
        inputs.len() <= u64::MAX as usize,
        "input count does not fit the profile encoding"
    );

    let mut state = [F::ZERO; WIDTH];
    state[0] += domain_tag(domain);
    state[1] += F::from(inputs.len() as u64);
    state = permutation_native(state);

    for pair in inputs.chunks(RATE) {
        state[0] += pair[0];
        if pair.len() == RATE {
            state[1] += pair[1];
        }
        state = permutation_native(state);
    }

    state[0]
}

/// Permute three allocated Pallas-base-field elements with exact Orchard
/// P128Pow5T3 constants. This materializes the three final linear
/// combinations, costing 243 R1CS constraints (240 S-box multiplications and
/// three output equalities).
pub fn permutation_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    state: &[AllocatedNum<F>; WIDTH],
) -> Result<[AllocatedNum<F>; WIDTH], SynthesisError> {
    let state = state.clone().map(Expr::from_allocated);
    let state = permutation_expr(cs.namespace(|| "poseidon"), state)?;
    Ok([
        state[0].materialize(cs.namespace(|| "output_0"))?,
        state[1].materialize(cs.namespace(|| "output_1"))?,
        state[2].materialize(cs.namespace(|| "output_2"))?,
    ])
}

/// The SAR-ZK sponge in Nova's R1CS frontend.
///
/// Linear layers stay as linear combinations until an S-box needs an actual
/// multiplication input. That is both sound and materially smaller than
/// allocating every addition and MDS row.
pub fn hash_gadget<CS: ConstraintSystem<F>>(
    mut cs: CS,
    domain: &str,
    inputs: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError> {
    assert!(
        inputs.len() <= u64::MAX as usize,
        "input count does not fit the profile encoding"
    );

    let one = CS::one();
    let mut state = core::array::from_fn(|_| Expr::zero());
    state[0].add_constant(domain_tag(domain), one);
    state[1].add_constant(F::from(inputs.len() as u64), one);
    state = permutation_expr(cs.namespace(|| "permutation_after_tag_length"), state)?;

    for (pair_index, pair) in inputs.chunks(RATE).enumerate() {
        state[0].add_expr(&Expr::from_allocated(pair[0].clone()));
        if pair.len() == RATE {
            state[1].add_expr(&Expr::from_allocated(pair[1].clone()));
        }
        state = permutation_expr(
            cs.namespace(|| format!("permutation_after_pair_{pair_index}")),
            state,
        )?;
    }

    state[0].materialize(cs.namespace(|| "digest"))
}

fn is_partial_round(round: usize) -> bool {
    (FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&round)
}

fn pow5_native(value: F) -> F {
    let square = value.square();
    square.square() * value
}

fn apply_mds_native(state: &[F; WIDTH], mds: &[[F; WIDTH]; WIDTH]) -> [F; WIDTH] {
    core::array::from_fn(|row| {
        (0..WIDTH).fold(F::ZERO, |acc, column| {
            acc + mds[row][column] * state[column]
        })
    })
}

fn permutation_expr<CS: ConstraintSystem<F>>(
    mut cs: CS,
    mut state: [Expr; WIDTH],
) -> Result<[Expr; WIDTH], SynthesisError> {
    let constants = constants();
    let one = CS::one();
    for (round, round_constants) in constants.round_constants.iter().enumerate() {
        let partial = is_partial_round(round);
        for word in 0..WIDTH {
            state[word].add_constant(round_constants[word], one);
            if !partial || word == 0 {
                state[word] = pow5_expr(
                    cs.namespace(|| format!("round_{round}_sbox_{word}")),
                    &state[word],
                )?;
            }
        }
        state = apply_mds_expr(&state, &constants.mds);
    }
    Ok(state)
}

fn pow5_expr<CS: ConstraintSystem<F>>(mut cs: CS, input: &Expr) -> Result<Expr, SynthesisError> {
    let square = input.multiply(cs.namespace(|| "square"), input)?;
    let fourth = square.multiply(cs.namespace(|| "fourth"), &square)?;
    fourth.multiply(cs.namespace(|| "fifth"), input)
}

fn apply_mds_expr(state: &[Expr; WIDTH], mds: &[[F; WIDTH]; WIDTH]) -> [Expr; WIDTH] {
    core::array::from_fn(|row| {
        let mut output = Expr::zero();
        for column in 0..WIDTH {
            output.add_scaled(&state[column], mds[row][column]);
        }
        output
    })
}

/// A witness value together with its unmaterialized linear combination.
///
/// The value may be absent while `ShapeCS` is determining circuit shape. It
/// is read only inside allocation closures so shape synthesis never fails for
/// lack of a concrete assignment.
#[derive(Clone)]
struct Expr {
    value: Option<F>,
    lc: LinearCombination<F>,
}

impl Expr {
    fn zero() -> Self {
        Self {
            value: Some(F::ZERO),
            lc: LinearCombination::zero(),
        }
    }

    fn from_allocated(value: AllocatedNum<F>) -> Self {
        Self {
            value: value.get_value(),
            lc: LinearCombination::zero() + value.get_variable(),
        }
    }

    fn add_constant(&mut self, constant: F, one: Variable) {
        self.value = self.value.map(|value| value + constant);
        self.lc = self.lc.clone() + (constant, one);
    }

    fn add_expr(&mut self, other: &Self) {
        self.value = match (self.value, other.value) {
            (Some(left), Some(right)) => Some(left + right),
            _ => None,
        };
        self.lc = self.lc.clone() + &other.lc;
    }

    fn add_scaled(&mut self, other: &Self, scalar: F) {
        self.value = match (self.value, other.value) {
            (Some(left), Some(right)) => Some(left + scalar * right),
            _ => None,
        };
        self.lc = self.lc.clone() + (scalar, &other.lc);
    }

    fn multiply<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Self, SynthesisError> {
        let value = match (self.value, other.value) {
            (Some(left), Some(right)) => Some(left * right),
            _ => None,
        };
        let out = AllocatedNum::alloc(cs.namespace(|| "value"), || {
            value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce(
            || "constraint",
            |lc| lc + &self.lc,
            |lc| lc + &other.lc,
            |lc| lc + out.get_variable(),
        );
        Ok(Self::from_allocated(out))
    }

    fn materialize<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        let out = AllocatedNum::alloc(cs.namespace(|| "value"), || {
            self.value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce(
            || "constraint",
            |lc| lc + &self.lc,
            |lc| lc + CS::one(),
            |lc| lc + out.get_variable(),
        );
        Ok(out)
    }
}

fn constants() -> &'static Constants {
    CONSTANTS.get_or_init(|| {
        let (round_constants, mds, _) = orchard_constants();
        let round_constants: Vec<[F; WIDTH]> = round_constants
            .into_iter()
            .map(|row| row.map(from_orchard))
            .collect();
        let round_constants: [[F; WIDTH]; ROUNDS] = round_constants
            .try_into()
            .expect("P128Pow5T3 has exactly 64 rounds");
        Constants {
            round_constants,
            mds: mds.map(|row| row.map(from_orchard)),
        }
    })
}

#[cfg(test)]
fn to_orchard(value: F) -> OrchardFp {
    let repr = <F as PrimeField13>::to_repr(&value);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(repr.as_ref());
    Option::<OrchardFp>::from(<OrchardFp as PrimeField14>::from_repr(bytes))
        .expect("a canonical Pallas Fp value remains canonical across the Pasta versions")
}

fn from_orchard(value: OrchardFp) -> F {
    let repr = <OrchardFp as PrimeField14>::to_repr(&value);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(repr.as_ref());
    Option::<F>::from(<F as PrimeField13>::from_repr(bytes.into()))
        .expect("a canonical Pallas Fp value remains canonical across the Pasta versions")
}

fn orchard_constants() -> (
    Vec<[OrchardFp; WIDTH]>,
    Mds<OrchardFp, WIDTH>,
    Mds<OrchardFp, WIDTH>,
) {
    <P128Pow5T3 as Spec<OrchardFp, WIDTH, RATE>>::constants()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use nova_snark::frontend::{test_cs::TestConstraintSystem, ConstraintSystem};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn halo2_permutation(input: [F; WIDTH]) -> [F; WIDTH] {
        let mut state = input.map(to_orchard);
        let (round_constants, mds, _) = orchard_constants();
        halo2_poseidon::test_only_permute::<OrchardFp, P128Pow5T3, WIDTH, RATE>(
            &mut state,
            &mds,
            &round_constants,
        );
        state.map(from_orchard)
    }

    #[test]
    fn native_permutation_matches_halo2_boundary_and_random_states() {
        let mut cases = vec![
            [F::ZERO; WIDTH],
            [F::ONE, F::from(2), F::from(3)],
            [-F::ONE; WIDTH],
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(0x5341_522d_5a4b);
        cases.extend((0..32).map(|_| {
            [
                F::random(&mut rng),
                F::random(&mut rng),
                F::random(&mut rng),
            ]
        }));
        for (case, input) in cases.into_iter().enumerate() {
            assert_eq!(
                permutation_native(input),
                halo2_permutation(input),
                "case {case}"
            );
        }
    }

    #[test]
    fn native_and_gadget_permutations_match_random_states() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x504f_5345_4944_4f4e);
        for case in 0..8 {
            let input = [
                F::random(&mut rng),
                F::random(&mut rng),
                F::random(&mut rng),
            ];
            let native = permutation_native(input);
            let mut cs = TestConstraintSystem::<F>::new();
            let state = core::array::from_fn(|word| {
                AllocatedNum::alloc(cs.namespace(|| format!("input_{word}")), || Ok(input[word]))
                    .unwrap()
            });
            let output = permutation_gadget(cs.namespace(|| "permutation"), &state).unwrap();
            assert!(
                cs.is_satisfied(),
                "case {case}: {:?}",
                cs.which_is_unsatisfied()
            );
            for word in 0..WIDTH {
                assert_eq!(
                    output[word].get_value(),
                    Some(native[word]),
                    "case {case}, word {word}"
                );
            }
            if case == 0 {
                eprintln!("Poseidon permutation constraints: {}", cs.num_constraints());
            }
            assert_eq!(cs.num_constraints(), 243, "case {case}");
        }
    }

    #[test]
    fn native_and_gadget_sponge_match_random_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5350_4f4e_4745);
        for len in 0..=8 {
            let input: Vec<F> = (0..len).map(|_| F::random(&mut rng)).collect();
            let native = hash_native("SAR-ZK transcript", &input);
            let mut cs = TestConstraintSystem::<F>::new();
            let allocated = input
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input_{i}")), || Ok(*value))
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let output =
                hash_gadget(cs.namespace(|| "hash"), "SAR-ZK transcript", &allocated).unwrap();
            assert!(
                cs.is_satisfied(),
                "len {len}: {:?}",
                cs.which_is_unsatisfied()
            );
            assert_eq!(output.get_value(), Some(native), "len {len}");
        }
    }

    #[test]
    fn domain_label_and_input_framing_are_unambiguous() {
        assert_eq!(domain_tag("ab"), F::from(0x6162));
        assert_ne!(
            hash_native("SAR-ZK nk", &[F::from(1)]),
            hash_native("SAR-ZK n", &[F::from(107), F::from(107)])
        );
        assert_ne!(
            hash_native("SAR-ZK nk", &[F::from(9)]),
            hash_native("SAR-ZK nk", &[F::from(9), F::ZERO])
        );
        assert_ne!(
            hash_native("SAR-ZK nk", &[]),
            hash_native("SAR-ZK nk", &[F::ZERO])
        );
        assert!(std::panic::catch_unwind(|| domain_tag("x".repeat(32).as_str())).is_err());
        assert!(std::panic::catch_unwind(|| domain_tag("\u{80}")).is_err());
    }
}
