//! Constraint-level hostile tests for the profile-b relation.
//!
//! These deliberately inspect satisfiability of Nova's test constraint system.
//! A native `false` or an early synthesis error is never treated as a defence.

use ff::Field;
use nova_snark::{
    frontend::{
        num::AllocatedNum, shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem,
    },
    traits::circuit::StepCircuit,
};
use zkar_prover::{
    issuance::Fixture,
    relation::{
        acc_native, nullifier_native, policy_commitment_native, transcript_start_native,
        transcript_step_native, Branch, Pc, State, ACC, KIND_EGRESS, KIND_FILE, KIND_PADDING,
        KIND_TOOL, OUT, PC, POLICY_COMMITMENT, TREE_SIZE,
    },
    E1, F,
};

fn fixture() -> Fixture {
    // T=4 gives tool, egress, file, payment and two explicit padding folds.
    Fixture::benchmark_deterministic(4, 8, 3, 0x5341_522d_5a4b).unwrap()
}

fn synthesize<C: StepCircuit<F>>(circuit: &C, input: State) -> TestConstraintSystem<F> {
    let mut cs = TestConstraintSystem::<F>::new();
    let state = input
        .iter()
        .enumerate()
        .map(|(index, value)| {
            AllocatedNum::alloc(cs.namespace(|| format!("state_{index}")), || Ok(*value))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // Invalid witnesses must become unsatisfied constraints, not a skipped
    // test because a caller ignored an early synthesis error.
    circuit
        .synthesize(&mut cs, &state)
        .expect("relation synthesis must not be the rejection path");
    cs
}

fn is_sat<C: StepCircuit<F>>(circuit: &C, input: State) -> bool {
    synthesize(circuit, input).is_satisfied()
}

fn assert_unsat_at<C: StepCircuit<F>>(circuit: &C, input: State, expected: &str) {
    let cs = synthesize(circuit, input);
    assert!(!cs.is_satisfied(), "GOT THROUGH; expected {expected}");
    let failed = cs.which_is_unsatisfied().unwrap_or("no failed constraint");
    assert!(
        failed.contains(expected),
        "expected {expected:?}, got {failed:?}"
    );
}

/// Compare the nullifier the circuit computed with `expected_out`. This shows
/// what the circuit computes on this witness. It does not, by itself, show
/// that the constraints fix the output: `tests/output_constraints.rs` checks
/// that.
fn is_sat_with_out_forced<C: StepCircuit<F>>(circuit: &C, input: State, expected_out: F) -> bool {
    let mut cs = TestConstraintSystem::<F>::new();
    let state = input
        .iter()
        .enumerate()
        .map(|(index, value)| {
            AllocatedNum::alloc(cs.namespace(|| format!("state_{index}")), || Ok(*value))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let output = circuit.synthesize(&mut cs, &state).unwrap();
    cs.enforce(
        || "test expected nullifier",
        |lc| lc + output[OUT].get_variable() + (-expected_out, TestConstraintSystem::<F>::one()),
        |lc| lc + TestConstraintSystem::<F>::one(),
        |lc| lc,
    );
    cs.is_satisfied()
}

fn two_to(power: usize) -> F {
    let mut result = F::ONE;
    for _ in 0..power {
        result = result.double();
    }
    result
}

fn shape<C: StepCircuit<F>>(circuit: &C) -> (usize, usize, usize, String) {
    let mut cs = ShapeCS::<E1>::new();
    let state = (0..circuit.arity())
        .map(|index| AllocatedNum::alloc(cs.namespace(|| format!("state_{index}")), || Ok(F::ZERO)))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    circuit.synthesize(&mut cs, &state).unwrap();
    (
        cs.num_constraints(),
        cs.num_inputs(),
        cs.num_aux(),
        format!("{:?}", cs.constraints),
    )
}

#[test]
fn honest_direct_and_uniform_traces_are_satisfied() {
    let fixture = fixture();
    for step in fixture.branch_steps_unpadded() {
        assert!(
            is_sat(&step.circuit, step.input),
            "direct {:?} must satisfy",
            step.circuit.branch
        );
    }
    for (index, step) in fixture.uniform_steps().into_iter().enumerate() {
        assert!(
            is_sat(&step.circuit, step.input),
            "uniform fold {index} must satisfy"
        );
    }
}

#[test]
fn uniform_shape_is_identical_for_start_every_kind_padding_and_final() {
    let fixture = fixture();
    let trace = fixture.uniform_steps();
    assert_eq!(
        trace.len(),
        8,
        "T=4 should pad 6 real/start/final folds to 8"
    );
    let expected = shape(&trace[0].circuit);
    // start, tool, egress, file, payment, padding, padding, final
    for (index, step) in trace.iter().enumerate() {
        assert_eq!(
            shape(&step.circuit),
            expected,
            "uniform shape changed at fold {index}"
        );
    }
}

#[test]
fn standalone_step_shape_is_independent_of_entry_kind() {
    let fixture = fixture();
    let trace = fixture.branch_steps_unpadded();
    let expected = shape(&trace[1].circuit); // tool
    for (index, step) in trace.iter().enumerate().skip(1).take(4) {
        assert_eq!(step.circuit.branch, Branch::Step);
        assert_eq!(
            shape(&step.circuit),
            expected,
            "step shape changed for entry {index}"
        );
    }
}

#[test]
fn unknown_pc_halt_and_nonzero_out_cannot_transition() {
    let fixture = fixture();
    let trace = fixture.uniform_steps();
    let ordinary_step = &trace[1];
    let mut unknown = ordinary_step.input;
    unknown[PC] = F::from(99);
    assert!(
        !is_sat(&ordinary_step.circuit, unknown),
        "unknown pc GOT THROUGH"
    );
    let mut halt = ordinary_step.input;
    halt[PC] = Pc::Halt.field();
    assert!(
        !is_sat(&ordinary_step.circuit, halt),
        "HALT transition GOT THROUGH"
    );
    let mut nonzero_out = ordinary_step.input;
    nonzero_out[OUT] = F::ONE;
    assert!(
        !is_sat(&ordinary_step.circuit, nonzero_out),
        "out before final GOT THROUGH"
    );
}

#[test]
fn tool_egress_unknown_kind_padding_and_digest_limbs_are_constrained() {
    let fixture = fixture();
    let trace = fixture.uniform_steps();

    // Tool membership path no longer matches a different 128-bit digest.
    let mut tool = trace[1].circuit.clone();
    tool.step.entry.d_hi += F::ONE;
    assert!(
        !is_sat(&tool, trace[1].input),
        "off-allowlist tool GOT THROUGH"
    );

    // Re-open the accumulator and public policy consistently, then turn off
    // egress: this reaches the actual egress gate rather than only an acc
    // opening mismatch.
    let mut egress = trace[2].circuit.clone();
    assert_eq!(egress.step.entry.kind, F::from(KIND_EGRESS));
    egress.step.opening.policy.egress_allowed = F::ZERO;
    let mut egress_input = trace[2].input;
    egress_input[ACC] = acc_native(egress.step.opening);
    egress_input[POLICY_COMMITMENT] = policy_commitment_native(egress.step.opening.policy);
    assert!(
        !is_sat(&egress, egress_input),
        "disallowed egress GOT THROUGH"
    );

    let mut unknown_kind = trace[1].circuit.clone();
    unknown_kind.step.entry.kind = F::from(5);
    assert!(
        !is_sat(&unknown_kind, trace[1].input),
        "unknown kind GOT THROUGH"
    );

    // The fixture contains explicit padding and it satisfies. A padding
    // digest outside the 128-bit SHA-256 limb range does not.
    assert_eq!(trace[5].circuit.step.entry.kind, F::from(KIND_PADDING));
    assert!(is_sat(&trace[5].circuit, trace[5].input));
    let mut bad_padding = trace[5].circuit.clone();
    bad_padding.step.entry.d_hi = two_to(128);
    assert!(
        !is_sat(&bad_padding, trace[5].input),
        "wide padding digest GOT THROUGH"
    );
}

#[test]
fn final_checks_count_profile_signature_opening_and_membership() {
    let fixture = fixture();
    let trace = fixture.branch_steps_unpadded();
    let final_step = trace.last().unwrap();

    let mut profile = final_step.circuit.clone();
    profile.final_witness.statement.profile_tag = F::from(10);
    assert_unsat_at(&profile, final_step.input, "statement profile b");

    let mut bad_opening = final_step.circuit.clone();
    bad_opening.final_witness.r += F::ONE;
    assert_unsat_at(&bad_opening, final_step.input, "nk opening");

    let mut wrong_nk = final_step.circuit.clone();
    wrong_nk.final_witness.nk += F::ONE;
    assert_unsat_at(&wrong_nk, final_step.input, "nk opening");

    let mut bad_path = final_step.circuit.clone();
    bad_path.final_witness.log_path[0] += F::ONE;
    assert_unsat_at(&bad_path, final_step.input, "log root");

    let mut bad_index = final_step.circuit.clone();
    bad_index.final_witness.leaf_index = F::from(8);
    assert_unsat_at(&bad_index, final_step.input, "leaf index below tree size");

    let mut bad_signature = final_step.circuit.clone();
    bad_signature.final_witness.signature.s += zkar_prover::schnorr::Scalar::ONE;
    assert_unsat_at(&bad_signature, final_step.input, "issuer schnorr signature");

    let mut bad_rho = final_step.circuit.clone();
    bad_rho.final_witness.opening.rho += F::ONE;
    assert_unsat_at(&bad_rho, final_step.input, "acc opening matches state");

    let mut bad_count = final_step.circuit.clone();
    bad_count.final_witness.opening.index = two_to(32);
    let mut count_input = final_step.input;
    count_input[ACC] = acc_native(bad_count.final_witness.opening);
    assert_unsat_at(&bad_count, count_input, "index u32");

    let mut bad_tree_size = final_step.input;
    bad_tree_size[TREE_SIZE] = two_to(31);
    assert_unsat_at(&final_step.circuit, bad_tree_size, "tree size below 2^31");
}

#[test]
fn changed_or_dropped_non_tool_entries_cannot_match_the_signed_transcript() {
    let fixture = fixture();
    let trace = fixture.branch_steps_unpadded();
    let final_step = trace.last().unwrap();

    let mut changed_entries = fixture.entries.clone();
    assert_eq!(changed_entries[2].kind, F::from(KIND_FILE));
    changed_entries[2].d_lo += F::ONE;
    let mut changed_transcript = transcript_start_native(fixture.start.task_binding);
    for (position, entry) in changed_entries.iter().enumerate() {
        changed_transcript =
            transcript_step_native(changed_transcript, F::from((position + 1) as u64), entry);
    }
    let mut changed = final_step.circuit.clone();
    changed.final_witness.opening.transcript = changed_transcript;
    let mut changed_input = final_step.input;
    changed_input[ACC] = acc_native(changed.final_witness.opening);
    assert_unsat_at(&changed, changed_input, "statement transcript matches acc");

    // A three-entry prefix has an internally consistent accumulator opening,
    // but it cannot satisfy the signed four-entry transcript/count.
    let mut short_transcript = transcript_start_native(fixture.start.task_binding);
    for (position, entry) in fixture.entries[..3].iter().enumerate() {
        short_transcript =
            transcript_step_native(short_transcript, F::from((position + 1) as u64), entry);
    }
    let mut dropped = final_step.circuit.clone();
    dropped.final_witness.opening.transcript = short_transcript;
    dropped.final_witness.opening.index = F::from(3);
    dropped.final_witness.opening.pay_count = F::ZERO;
    let mut dropped_input = final_step.input;
    dropped_input[ACC] = acc_native(dropped.final_witness.opening);
    assert_unsat_at(&dropped, dropped_input, "statement transcript matches acc");
}

#[test]
fn final_out_is_the_nullifier_for_the_pinned_scope_only() {
    let fixture = fixture();
    let final_step = fixture.branch_steps_unpadded().pop().unwrap();
    let other_scope = fixture.public_bind.nullifier_scope + F::ONE;
    let wrong = nullifier_native(fixture.nk, other_scope);
    // The final circuit reads the original public scope in z. Adding a test
    // constraint that identifies its output with H(nk, other_scope) must fail.
    assert!(
        !is_sat_with_out_forced(&final_step.circuit, final_step.input, wrong),
        "cross-scope nullifier GOT THROUGH"
    );
}

#[test]
fn payment_bound_is_checked_at_final_not_by_host_logic() {
    let fixture = fixture();
    let trace = fixture.branch_steps_unpadded();
    let final_step = trace.last().unwrap();
    let mut circuit = final_step.circuit.clone();
    // T=4 includes exactly one payment, so bound zero is a real policy
    // violation. Rebind the accumulator and public policy to isolate the
    // final count comparator.
    circuit.final_witness.opening.policy.payment_bound = F::ZERO;
    let mut input = final_step.input;
    input[ACC] = acc_native(circuit.final_witness.opening);
    input[POLICY_COMMITMENT] = policy_commitment_native(circuit.final_witness.opening.policy);
    assert_unsat_at(&circuit, input, "payment count bounded");
}

#[test]
fn payment_and_count_fields_have_independent_u32_boundaries() {
    let fixture = fixture();
    let final_step = fixture.branch_steps_unpadded().pop().unwrap();

    let mut wide_payment_count = final_step.circuit.clone();
    wide_payment_count.final_witness.opening.pay_count = two_to(32);
    let mut count_input = final_step.input;
    count_input[ACC] = acc_native(wide_payment_count.final_witness.opening);
    assert_unsat_at(&wide_payment_count, count_input, "pay count u32");

    let mut wide_payment_bound = final_step.circuit.clone();
    wide_payment_bound
        .final_witness
        .opening
        .policy
        .payment_bound = two_to(32);
    let mut bound_input = final_step.input;
    bound_input[ACC] = acc_native(wide_payment_bound.final_witness.opening);
    bound_input[POLICY_COMMITMENT] =
        policy_commitment_native(wide_payment_bound.final_witness.opening.policy);
    assert_unsat_at(&wide_payment_bound, bound_input, "payment bound u32");

    let mut max_bound = final_step.circuit.clone();
    max_bound.final_witness.opening.policy.payment_bound = two_to(32) - F::ONE;
    let mut max_input = final_step.input;
    max_input[ACC] = acc_native(max_bound.final_witness.opening);
    max_input[POLICY_COMMITMENT] = policy_commitment_native(max_bound.final_witness.opening.policy);
    assert!(
        is_sat(&max_bound, max_input),
        "u32::MAX payment bound must be accepted"
    );
}

#[test]
fn issuance_is_seed_deterministic_but_rho_nullifier_and_signing_are_bound() {
    let a = Fixture::benchmark_deterministic(4, 8, 3, 44).unwrap();
    let b = Fixture::benchmark_deterministic(4, 8, 3, 44).unwrap();
    let c = Fixture::benchmark_deterministic(4, 8, 3, 45).unwrap();
    assert_eq!(a.initial_state(), b.initial_state());
    assert_eq!(a.expected_final_state(), b.expected_final_state());
    assert_ne!(a.nullifier, c.nullifier);
    assert_eq!(a.candidate_set_size, 8);
    assert_eq!(a.log_leaves, 8);
    assert_eq!(a.public_bind.profile_tag, F::from(11));
    assert_eq!(a.entries[0].kind, F::from(KIND_TOOL));
}
