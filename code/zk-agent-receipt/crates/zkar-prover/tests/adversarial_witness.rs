//! Adversarial witness tests: hostile witnesses against the uniform SAR-ZK circuit.
//!
//! Each test builds a malicious witness or forces a malicious output and
//! checks R1CS satisfiability with Nova's TestConstraintSystem. A satisfied
//! system for a false statement would be a confirmed break. Every test below
//! asserts the attack is REJECTED, except where it asserts that an inactive
//! branch may legitimately carry attacker data (and then shows it cannot leak).

use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem},
    traits::circuit::StepCircuit,
};
use zkar_prover::{
    issuance::Fixture,
    relation::{
        acc_native, policy_commitment_native, AccOpening, Pc, State, TraceStep, UniformCircuit,
        ACC, KIND_PADDING, KIND_PAYMENT, KIND_TOOL, OUT, PC, POLICY_COMMITMENT, TREE_SIZE,
    },
    schnorr, F,
};

fn fixture(seed: u64) -> Fixture {
    // T=4: start, tool, egress, file, payment, pad, pad, final.
    Fixture::benchmark_deterministic(4, 8, 3, seed).unwrap()
}

fn trace(seed: u64) -> Vec<TraceStep<UniformCircuit>> {
    fixture(seed).uniform_steps()
}

const SEED_A: u64 = 0x4345_5254_494b_0001;
const SEED_B: u64 = 0x4345_5254_494b_0002;

struct Run {
    sat: bool,
    failed: String,
    out: Vec<Option<F>>,
}

/// Synthesize `circuit` on `input`, then add test constraints forcing chosen
/// output slots to chosen values.
///
/// The synthesis assigns each output the value the circuit computed. A forced
/// constraint therefore compares that computed value with the chosen one. It
/// shows what the circuit computes on this witness. It does not, by itself,
/// show that the constraints fix the output: `tests/output_constraints.rs`
/// checks that.
fn run<C: StepCircuit<F>>(circuit: &C, input: State, forced: &[(usize, F)]) -> Run {
    let mut cs = TestConstraintSystem::<F>::new();
    let z = input
        .iter()
        .enumerate()
        .map(|(i, v)| AllocatedNum::alloc(cs.namespace(|| format!("z_{i}")), || Ok(*v)))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let out = circuit
        .synthesize(&mut cs, &z)
        .expect("hostile witness must give unsat R1CS, not a synthesis error");
    let values = out.iter().map(|n| n.get_value()).collect();
    for (k, (slot, value)) in forced.iter().enumerate() {
        let var = out[*slot].get_variable();
        let v = *value;
        cs.enforce(
            || format!("forced output {k}"),
            |lc| lc + var + (-v, TestConstraintSystem::<F>::one()),
            |lc| lc + TestConstraintSystem::<F>::one(),
            |lc| lc,
        );
    }
    Run {
        sat: cs.is_satisfied(),
        failed: cs.which_is_unsatisfied().unwrap_or("").to_owned(),
        out: values,
    }
}

fn two_to(power: usize) -> F {
    (0..power).fold(F::ONE, |acc, _| acc.double())
}

fn unsat<C: StepCircuit<F>>(
    circuit: &C,
    input: State,
    forced: &[(usize, F)],
    what: &str,
) -> String {
    let r = run(circuit, input, forced);
    assert!(!r.sat, "BREAK: {what} GOT THROUGH");
    r.failed
}

// ---------------------------------------------------------------------------
// 1. Branch selection

#[test]
fn a01_honest_trace_satisfies_and_outputs_match_native() {
    for (i, step) in trace(SEED_A).iter().enumerate() {
        let r = run(&step.circuit, step.input, &[]);
        assert!(r.sat, "honest fold {i} unsat at {}", r.failed);
        let got: Vec<F> = r.out.iter().map(|v| v.unwrap()).collect();
        assert_eq!(
            got,
            step.output.to_vec(),
            "fold {i} output differs from native"
        );
    }
}

#[test]
fn a02_final_flag_is_ignored_when_pc_is_start() {
    let t = trace(SEED_A);
    let mut c = t[0].circuit.clone();
    c.final_flag = true;
    let r = run(&c, t[0].input, &[]);
    assert!(
        r.sat,
        "start with flag set should still be the start branch"
    );
    assert_eq!(
        r.out[PC],
        Some(Pc::Step.field()),
        "flag leaked into pc at START"
    );
    assert_eq!(r.out[OUT], Some(F::ZERO));
    let f = unsat(&c, t[0].input, &[(PC, Pc::Halt.field())], "FINAL at START");
    eprintln!("a02 forced HALT at START rejected by: {f}");
}

#[test]
fn a03_final_before_all_entries_are_folded() {
    let t = trace(SEED_A);
    // After tool and egress (input of fold 3), acc opens to a two-entry prefix.
    // The inactive step branch must get a witness valid for its fallback state.
    let mut c = t[3].circuit.clone();
    c.final_flag = true;
    c.step = t[7].circuit.step.clone();
    c.final_witness.opening = t[3].circuit.step.opening;
    let f = unsat(
        &c,
        t[3].input,
        &[],
        "early FINAL with consistent prefix opening",
    );
    assert!(f.contains("statement transcript matches acc"), "{f}");
    // Same, but keep the real final opening: it no longer opens the state acc.
    let mut c = t[3].circuit.clone();
    c.final_flag = true;
    c.step = t[7].circuit.step.clone();
    let f = unsat(&c, t[3].input, &[], "early FINAL with full opening");
    assert!(f.contains("acc opening matches state"), "{f}");
}

#[test]
fn a04_no_transition_after_halt() {
    let t = trace(SEED_A);
    let halted = t[7].output;
    for idx in [1usize, 5, 7] {
        for flag in [false, true] {
            let mut c = t[idx].circuit.clone();
            c.final_flag = flag;
            let f = unsat(&c, halted, &[], "transition from HALT");
            assert!(f.contains("pc is recognized"), "{f}");
        }
    }
}

#[test]
fn a05_start_cannot_run_twice() {
    let t = trace(SEED_A);
    for idx in [1usize, 4, 7] {
        let mut input = t[idx].input;
        input[PC] = Pc::Start.field();
        let mut c = t[0].circuit.clone();
        c.final_flag = false;
        let f = unsat(&c, input, &[], "second START over a live acc");
        assert!(f.contains("initial acc zero"), "{f}");
    }
}

#[test]
fn a06_halt_or_nullifier_cannot_appear_without_final() {
    let fx = fixture(SEED_A);
    let t = fx.uniform_steps();
    for (i, step) in t.iter().enumerate().take(7) {
        unsat(
            &step.circuit,
            step.input,
            &[(PC, Pc::Halt.field())],
            "HALT without FINAL",
        );
        unsat(
            &step.circuit,
            step.input,
            &[(OUT, fx.nullifier)],
            "nullifier without FINAL",
        );
        unsat(
            &step.circuit,
            step.input,
            &[(ACC, F::ZERO)],
            "acc cleared without FINAL",
        );
        let _ = i;
    }
}

// There is no a07 here. An earlier a07 forced each output slot to a wrong
// value and expected an unsatisfied system. That check could not fail, because
// the forced constraint compares against the value the synthesis itself
// assigned. `tests/output_constraints.rs` checks at the constraint level that
// every output variable is pinned.

#[test]
fn a08_foreign_fallbacks_are_isolated() {
    let a = trace(SEED_A);
    let b = trace(SEED_B);
    let fb = fixture(SEED_B);
    // A's ordinary tool step, but every inactive branch carries B's data:
    // a different issuer, log, policy, nullifier scope and a valid FINAL.
    let mut c = a[1].circuit.clone();
    c.start = b[0].circuit.start.clone();
    c.start_fallback = b[0].input;
    c.final_witness = b[7].circuit.final_witness.clone();
    c.final_fallback = b[7].input;
    let r = run(&c, a[1].input, &[]);
    assert!(
        r.sat,
        "inactive branches on foreign valid states should satisfy: {}",
        r.failed
    );
    let got: Vec<F> = r.out.iter().map(|v| v.unwrap()).collect();
    assert_eq!(
        got,
        a[1].output.to_vec(),
        "foreign fallback leaked into output"
    );
    unsat(
        &c,
        a[1].input,
        &[(PC, Pc::Halt.field())],
        "foreign FINAL leaked pc",
    );
    unsat(
        &c,
        a[1].input,
        &[(OUT, fb.nullifier)],
        "foreign FINAL leaked nullifier",
    );

    // A's final fold with B's (self-consistent) final witness and fallback.
    let mut c = a[7].circuit.clone();
    c.final_witness = b[7].circuit.final_witness.clone();
    c.final_fallback = b[7].input;
    let f = unsat(&c, a[7].input, &[], "FINAL with foreign issuer/log witness");
    eprintln!("a08 foreign FINAL rejected by: {f}");
}

// ---------------------------------------------------------------------------
// 2. Blinded acc opening

#[test]
fn a09_no_acc_field_can_change_between_folds() {
    let t = trace(SEED_A);
    let step = &t[4]; // payment entry
    type Mut = fn(&mut AccOpening);
    let muts: [(&str, Mut); 7] = [
        ("transcript", |o| o.transcript += F::ONE),
        ("index", |o| o.index += F::ONE),
        ("pay_count", |o| o.pay_count -= F::ONE),
        ("allowlist_root", |o| o.policy.allowlist_root += F::ONE),
        ("egress_allowed", |o| o.policy.egress_allowed = F::ZERO),
        ("payment_bound", |o| o.policy.payment_bound += F::ONE),
        ("rho", |o| o.rho += F::ONE),
    ];
    for (name, m) in muts {
        let mut c = step.circuit.clone();
        m(&mut c.step.opening);
        let f = unsat(&c, step.input, &[], name);
        eprintln!("a09 {name}: {f}");
    }
    // The payment step must increment pay_count: forcing the output acc to the
    // opening with an unchanged count is rejected.
    let mut cheat = step.circuit.step.opening;
    let next = t[5].circuit.step.opening; // honest opening after the payment
    cheat.transcript = next.transcript;
    cheat.index = next.index;
    unsat(
        &step.circuit,
        step.input,
        &[(ACC, acc_native(cheat))],
        "payment not counted",
    );
}

#[test]
fn a10_final_index_must_equal_signed_step_count() {
    let t = trace(SEED_A);
    let mut c = t[7].circuit.clone();
    c.final_witness.opening.index += F::ONE;
    let mut input = t[7].input;
    input[ACC] = acc_native(c.final_witness.opening);
    let f = unsat(&c, input, &[], "i != step_count");
    assert!(f.contains("statement count matches acc"), "{f}");
    // Change the statement count to match a different i: the signature fails.
    let mut c = t[7].circuit.clone();
    c.final_witness.opening.index += F::ONE;
    c.final_witness.statement.step_count += F::ONE;
    let f = unsat(&c, input, &[], "re-signed count");
    assert!(f.contains("issuer schnorr signature"), "{f}");
}

#[test]
fn a11_padding_cannot_count_or_pay() {
    let t = trace(SEED_A);
    let pad = &t[5];
    assert_eq!(pad.circuit.step.entry.kind, F::from(KIND_PADDING));
    let mut o = pad.circuit.step.opening;
    o.index += F::ONE;
    unsat(
        &pad.circuit,
        pad.input,
        &[(ACC, acc_native(o))],
        "padding increments i",
    );
    let mut o = pad.circuit.step.opening;
    o.pay_count += F::ONE;
    unsat(
        &pad.circuit,
        pad.input,
        &[(ACC, acc_native(o))],
        "padding increments pay",
    );
    for kind in [
        F::from(5),
        -F::ONE,
        two_to(32) + F::ONE,
        F::from(KIND_PAYMENT) + two_to(64),
    ] {
        let mut c = pad.circuit.clone();
        c.step.entry.kind = kind;
        let f = unsat(&c, pad.input, &[], "unknown kind");
        assert!(f.contains("known entry kind"), "{f}");
    }
}

// ---------------------------------------------------------------------------
// 3. Range checks

#[test]
fn a12_tree_size_bound_is_exactly_1_to_2_pow_31_minus_1() {
    let t = trace(SEED_A);
    let file_step = &t[3]; // does not read the log; isolates the public bind
    let mut ok = file_step.input;
    ok[TREE_SIZE] = two_to(31) - F::ONE;
    assert!(
        run(&file_step.circuit, ok, &[]).sat,
        "2^31-1 must be accepted"
    );
    for bad in [
        F::ZERO,
        two_to(31),
        two_to(32) - F::ONE,
        two_to(32),
        -F::ONE,
        -two_to(31),
    ] {
        let mut input = file_step.input;
        input[TREE_SIZE] = bad;
        let f = unsat(&file_step.circuit, input, &[], "tree size out of range");
        assert!(f.contains("tree size"), "{f}");
    }
}

#[test]
fn a13_leaf_index_cannot_wrap_or_exceed_tree_size() {
    let t = trace(SEED_A);
    let fin = &t[7];
    let honest = fin.circuit.final_witness.leaf_index;
    for bad in [
        F::from(8),
        honest + two_to(32),
        -F::ONE,
        honest - two_to(32),
    ] {
        let mut c = fin.circuit.clone();
        c.final_witness.leaf_index = bad;
        let f = unsat(&c, fin.input, &[], "leaf index out of range");
        eprintln!("a13 leaf_index: {f}");
    }
}

#[test]
fn a14_tool_index_and_policy_fields_are_canonical() {
    let t = trace(SEED_A);
    let tool = &t[1];
    assert_eq!(tool.circuit.step.entry.kind, F::from(KIND_TOOL));
    // 2^16 has the same low 16 bits as the honest index 0.
    let mut c = tool.circuit.clone();
    c.step.entry.allow_index = two_to(16);
    let f = unsat(&c, tool.input, &[], "allow index 2^16");
    assert!(f.contains("allow index 16-bit"), "{f}");

    // Non-boolean egress and wide payment bound at START, with the public
    // commitment rebound to the malformed policy.
    for (name, egress, bound) in [
        ("egress 2", F::from(2), F::from(4)),
        ("egress -1", -F::ONE, F::from(4)),
        ("bound p-1", F::ONE, -F::ONE),
    ] {
        let mut c = t[0].circuit.clone();
        c.start.policy.egress_allowed = egress;
        c.start.policy.payment_bound = bound;
        let mut input = t[0].input;
        input[POLICY_COMMITMENT] = policy_commitment_native(c.start.policy);
        let f = unsat(&c, input, &[], name);
        eprintln!("a14 {name}: {f}");
    }
}

// ---------------------------------------------------------------------------
// 5. Schnorr gadget: the identity fallback must not become a forgery path

fn schnorr_cs(
    pk: schnorr::PallasPoint,
    r: schnorr::PallasPoint,
    s: schnorr::Scalar,
    m: F,
) -> TestConstraintSystem<F> {
    let mut cs = TestConstraintSystem::<F>::new();
    let pk = schnorr::alloc_point(cs.namespace(|| "pk"), pk).unwrap();
    let r = schnorr::alloc_point(cs.namespace(|| "r"), r).unwrap();
    let s = schnorr::alloc_scalar_bits(cs.namespace(|| "s"), s).unwrap();
    let m = AllocatedNum::alloc(cs.namespace(|| "m"), || Ok(m)).unwrap();
    schnorr::verify_gadget(cs.namespace(|| "verify"), &pk, &r, &s, &m).unwrap();
    cs
}

fn to_scalar(x: F) -> schnorr::Scalar {
    let mut repr = <schnorr::Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(x.to_repr().as_ref());
    Option::from(schnorr::Scalar::from_repr(repr)).unwrap()
}

#[test]
fn a15_offcurve_public_key_cannot_use_identity_fallback() {
    // If pk fell back to the identity, s·G = R + c·O = R holds for R = s·G and
    // any message: a universal forgery. Only the validity constraint stops it.
    let s = schnorr::Scalar::from(123_456_789u64);
    let r = schnorr::public_key(s);
    let bad_pk = schnorr::PallasPoint {
        x: F::ONE,
        y: F::ONE,
        is_identity: false,
    };
    assert!(!bad_pk.is_on_curve());
    let cs = schnorr_cs(bad_pk, r, s, F::from(42));
    assert!(
        !cs.is_satisfied(),
        "BREAK: off-curve pk forgery GOT THROUGH"
    );
    let f = cs.which_is_unsatisfied().unwrap();
    assert!(f.contains("public_key") && f.contains("on_curve"), "{f}");
}

#[test]
fn a16_offcurve_r_cannot_use_identity_fallback() {
    // With R off-curve and replaced by the identity, s = c·sk satisfies the
    // group equation natively. Only the validity constraint rejects it.
    let sk = schnorr::Scalar::from(987_654_321u64);
    let pk = schnorr::public_key(sk);
    let bad_r = schnorr::PallasPoint {
        x: F::ONE,
        y: F::ONE,
        is_identity: false,
    };
    let m = F::from(7);
    let c = to_scalar(schnorr::challenge(bad_r, pk, m));
    // s·G = (c·sk)·G = c·PK = O + c·PK by construction.
    let s = c * sk;
    let cs = schnorr_cs(pk, bad_r, s, m);
    assert!(!cs.is_satisfied(), "BREAK: off-curve R forgery GOT THROUGH");
    let f = cs.which_is_unsatisfied().unwrap();
    assert!(f.contains("verify/r/") && f.contains("on_curve"), "{f}");
}

#[test]
fn a17_identity_flag_with_valid_coordinates_is_rejected() {
    let sk = schnorr::Scalar::from(5u64);
    let pk = schnorr::public_key(sk);
    let k = schnorr::Scalar::from(11u64);
    let mut r = schnorr::public_key(k);
    let m = F::from(9);
    let c = to_scalar(schnorr::challenge(r, pk, m));
    let s = k + c * sk;
    assert!(
        schnorr_cs(pk, r, s, m).is_satisfied(),
        "honest signature must verify"
    );
    r.is_identity = true;
    let cs = schnorr_cs(pk, r, s, m);
    assert!(!cs.is_satisfied(), "BREAK: identity-flagged R GOT THROUGH");
    // And pk flagged identity.
    let mut pk_inf = pk;
    pk_inf.is_identity = true;
    r.is_identity = false;
    let cs = schnorr_cs(pk_inf, r, s, m);
    assert!(!cs.is_satisfied(), "BREAK: identity-flagged pk GOT THROUGH");
}
