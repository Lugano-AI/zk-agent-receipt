//! The profile-b SAR-ZK R1CS relation.
//!
//! This module deliberately keeps the native helpers and the R1CS gadgets
//! adjacent.  The native helpers construct a benchmark trace; they are never
//! used as a substitute for a circuit constraint.  In particular, every
//! value opened from `acc` is re-hashed in the circuit, and every check in the
//! final transition is an R1CS constraint.
//!
//! `UniformCircuit` is the fixed-shape circuit used by the Nova wrapper.  It
//! synthesizes start, step, and final candidates on every fold.  A constrained
//! mux feeds an inactive candidate a complete valid fallback state, rather
//! than merely skipping its constraints.  This is important: Poseidon and
//! elliptic-curve gadgets contain internal constraints which cannot safely be
//! disabled by gating only their final equality.

use crate::{poseidon, schnorr, F};
use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
        },
        ConstraintSystem, SynthesisError,
    },
    traits::circuit::StepCircuit,
};

/// Number of elements in the public IVC state, fixed by SAR-ZK §9.1.
pub const STATE_ARITY: usize = 9;

/// Indexes into [`State`].
pub const PC: usize = 0;
pub const ACC: usize = 1;
pub const PROFILE_TAG: usize = 2;
pub const ISSUER_KEY_COMMITMENT: usize = 3;
pub const LOG_ROOT: usize = 4;
pub const TREE_SIZE: usize = 5;
pub const POLICY_COMMITMENT: usize = 6;
pub const NULLIFIER_SCOPE: usize = 7;
pub const OUT: usize = 8;

/// Exact public state order: `(pc, acc, six public_bind values, out)`.
pub type State = [F; STATE_ARITY];

/// Program counter values.  The final transition deliberately enters with
/// `STEP`; `final_flag` selects it inside [`UniformCircuit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Pc {
    Start = 0,
    Step = 1,
    Halt = 2,
}

impl Pc {
    pub fn field(self) -> F {
        F::from(self as u64)
    }
}

/// The receipt profile implemented here is `sar-zk-v0.4b` (tag `0x0b`).
pub const PROFILE_B_TAG: u64 = 0x0b;
/// Fixed Merkle depths from SAR-ZK §§6 and 7.2.
pub const ALLOWLIST_DEPTH: usize = 16;
pub const LOG_DEPTH: usize = 32;
/// Canonical signed log-head tree-size ceiling (SAR-ZK §7.1).
pub const MAX_TREE_SIZE: u64 = 2_147_483_647;

/// Entry-kind field values.  Kind zero is proof-only padding.
pub const KIND_PADDING: u64 = 0;
pub const KIND_TOOL: u64 = 1;
pub const KIND_EGRESS: u64 = 2;
pub const KIND_FILE: u64 = 3;
pub const KIND_PAYMENT: u64 = 4;

/// Values the verifier fixes and that no transition may change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicBind {
    pub profile_tag: F,
    pub issuer_key_commitment: F,
    pub log_root: F,
    /// The canonical decimal tree size, represented in `F` in the circuit.
    pub tree_size: F,
    pub policy_commitment: F,
    pub nullifier_scope: F,
}

impl PublicBind {
    pub fn to_array(self) -> [F; 6] {
        [
            self.profile_tag,
            self.issuer_key_commitment,
            self.log_root,
            self.tree_size,
            self.policy_commitment,
            self.nullifier_scope,
        ]
    }

    pub fn initial_state(self) -> State {
        [
            Pc::Start.field(),
            F::ZERO,
            self.profile_tag,
            self.issuer_key_commitment,
            self.log_root,
            self.tree_size,
            self.policy_commitment,
            self.nullifier_scope,
            F::ZERO,
        ]
    }

    pub fn final_state(self, nullifier: F) -> State {
        [
            Pc::Halt.field(),
            F::ZERO,
            self.profile_tag,
            self.issuer_key_commitment,
            self.log_root,
            self.tree_size,
            self.policy_commitment,
            self.nullifier_scope,
            nullifier,
        ]
    }
}

/// The fixed-size statement `S` from SAR-ZK §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementWitness {
    pub profile_tag: F,
    pub task_binding: F,
    pub step_count: F,
    pub transcript: F,
    pub nk_commitment: F,
}

/// The policy opening carried inside `acc`.
///
/// These remain field elements rather than Rust booleans/integers so hostile
/// tests can give malformed values.  The circuit range- and bit-checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyOpening {
    pub allowlist_root: F,
    pub egress_allowed: F,
    pub payment_bound: F,
}

/// Opening of a blinded accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccOpening {
    pub transcript: F,
    pub index: F,
    pub pay_count: F,
    pub policy: PolicyOpening,
    pub rho: F,
}

/// One fixed-shape inventory-step witness.  `allow_path` is present for every
/// kind so the step circuit has a witness-independent shape; it is constrained
/// only for tool steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryWitness {
    pub kind: F,
    pub d_hi: F,
    pub d_lo: F,
    pub allow_index: F,
    pub allow_path: [F; ALLOWLIST_DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartWitness {
    pub task_binding: F,
    pub policy: PolicyOpening,
    pub rho: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepWitness {
    pub opening: AccOpening,
    pub entry: EntryWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalWitness {
    pub opening: AccOpening,
    pub statement: StatementWitness,
    pub issuer_pk: schnorr::PallasPoint,
    pub signature: schnorr::Signature,
    pub log_path: [F; LOG_DEPTH],
    pub leaf_index: F,
    pub nk: F,
    pub r: F,
}

/// Which standalone branch [`BranchCircuit`] realizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    Start,
    Step,
    Final,
}

/// A direct, one-branch circuit for monolithic/per-entry baselines and
/// per-branch constraint accounting.  Unlike [`UniformCircuit`], this only
/// synthesizes its named branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchCircuit {
    pub branch: Branch,
    pub start: StartWitness,
    pub step: StepWitness,
    pub final_witness: FinalWitness,
}

/// A fixed-shape, one-arity circuit that supports all three transitions.
///
/// `*_fallback` is a *valid* input state for its matching witness.  Inactive
/// candidates receive that state through a constrained mux.  This lets every
/// candidate's internal constraints remain live while only the selected
/// transition is tied to the actual Nova state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniformCircuit {
    /// Used only when `pc == STEP`: false chooses the normal step and true
    /// chooses final.  It is intentionally a witness, not a host branch.
    pub final_flag: bool,
    pub start: StartWitness,
    pub step: StepWitness,
    pub final_witness: FinalWitness,
    pub start_fallback: State,
    pub step_fallback: State,
    pub final_fallback: State,
}

/// One known transition in a native trace.  The proof wrapper consumes these
/// instead of simulating untrusted witnesses itself.
#[derive(Clone, Debug)]
pub struct TraceStep<C> {
    pub circuit: C,
    pub input: State,
    pub output: State,
}

// -------------------------------------------------------------------------
// Native arithmetic used for issuance/trace construction.  None of these
// functions authorize a proof; matching gadget constraints appear below.

pub fn policy_commitment_native(policy: PolicyOpening) -> F {
    poseidon::hash_native(
        "SAR-ZK policy",
        &[
            policy.allowlist_root,
            policy.egress_allowed,
            policy.payment_bound,
        ],
    )
}

pub fn transcript_start_native(task_binding: F) -> F {
    poseidon::hash_native("SAR-ZK transcript", &[task_binding])
}

pub fn transcript_step_native(previous: F, index: F, entry: &EntryWitness) -> F {
    poseidon::hash_native(
        "SAR-ZK step",
        &[previous, index, entry.kind, entry.d_hi, entry.d_lo],
    )
}

pub fn acc_native(opening: AccOpening) -> F {
    poseidon::hash_native(
        "SAR-ZK acc",
        &[
            opening.transcript,
            opening.index,
            opening.pay_count,
            opening.policy.allowlist_root,
            opening.policy.egress_allowed,
            opening.policy.payment_bound,
            opening.rho,
        ],
    )
}

pub fn statement_hash_native(statement: StatementWitness) -> F {
    poseidon::hash_native(
        "SAR-ZK statement",
        &[
            statement.profile_tag,
            statement.task_binding,
            statement.step_count,
            statement.transcript,
            statement.nk_commitment,
        ],
    )
}

pub fn log_leaf_native(statement_hash: F) -> F {
    poseidon::hash_native("SAR-ZK leaf", &[statement_hash])
}

pub fn allow_leaf_native(d_hi: F, d_lo: F) -> F {
    poseidon::hash_native("SAR-ZK allow", &[d_hi, d_lo])
}

pub fn nk_commitment_native(nk: F, r: F) -> F {
    poseidon::hash_native("SAR-ZK nk", &[nk, r])
}

pub fn nullifier_native(nk: F, scope: F) -> F {
    poseidon::hash_native("SAR-ZK nullifier", &[nk, scope])
}

pub fn issuer_key_commitment_native(pk: schnorr::PallasPoint) -> F {
    poseidon::hash_native("SAR-ZK issuer", &[pk.x, pk.y])
}

/// Native transition output for a correct start witness.  This is deliberately
/// a calculator, not a validator; R1CS re-enforces every relation.
pub fn start_output_native(bind: PublicBind, witness: &StartWitness) -> State {
    let opening = AccOpening {
        transcript: transcript_start_native(witness.task_binding),
        index: F::ZERO,
        pay_count: F::ZERO,
        policy: witness.policy,
        rho: witness.rho,
    };
    [
        Pc::Step.field(),
        acc_native(opening),
        bind.profile_tag,
        bind.issuer_key_commitment,
        bind.log_root,
        bind.tree_size,
        bind.policy_commitment,
        bind.nullifier_scope,
        F::ZERO,
    ]
}

/// Native transition output for a correct inventory/padding step.
pub fn step_output_native(input: State, witness: &StepWitness) -> State {
    let real = witness.entry.kind != F::from(KIND_PADDING);
    let mut opening = witness.opening;
    let next_index = opening.index + F::ONE;
    let stepped_transcript = transcript_step_native(opening.transcript, next_index, &witness.entry);
    if real {
        opening.transcript = stepped_transcript;
        opening.index = next_index;
        if witness.entry.kind == F::from(KIND_PAYMENT) {
            opening.pay_count += F::ONE;
        }
    }
    let mut output = input;
    output[PC] = Pc::Step.field();
    output[ACC] = acc_native(opening);
    output
}

/// Native transition output for a correct final witness.
pub fn final_output_native(bind: PublicBind, nk: F) -> State {
    bind.final_state(nullifier_native(nk, bind.nullifier_scope))
}

// -------------------------------------------------------------------------
// Nova StepCircuit entry points.

impl StepCircuit<F> for BranchCircuit {
    fn arity(&self) -> usize {
        STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let z = checked_state(z);
        enforce_public_bind(cs.namespace(|| "public bind"), z)?;
        let result = match self.branch {
            Branch::Start => synthesize_start(cs.namespace(|| "start"), z, &self.start)?,
            Branch::Step => synthesize_step(cs.namespace(|| "step"), z, &self.step)?,
            Branch::Final => synthesize_final(cs.namespace(|| "final"), z, &self.final_witness)?,
        };
        Ok(assemble_state(z, result))
    }
}

impl StepCircuit<F> for UniformCircuit {
    fn arity(&self) -> usize {
        STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let z = checked_state(z);
        enforce_public_bind(cs.namespace(|| "public bind"), z)?;

        // Reject `HALT` and every unknown pc.  `final_flag` only affects a
        // STEP input, exactly as SAR-ZK §9.1 requires.
        let is_start = is_equal_const(cs.namespace(|| "pc is start"), &z[PC], Pc::Start.field())?;
        let is_step_pc = is_equal_const(cs.namespace(|| "pc is step"), &z[PC], Pc::Step.field())?;
        enforce_allocated_bit_sum_one(
            cs.namespace(|| "pc is recognized"),
            &[&is_start, &is_step_pc],
        );

        let final_flag = AllocatedBit::alloc(cs.namespace(|| "final flag"), Some(self.final_flag))?;
        let final_flag = Boolean::from(final_flag);
        let is_final = Boolean::and(
            cs.namespace(|| "select final"),
            &Boolean::from(is_step_pc.clone()),
            &final_flag,
        )?;
        let is_step = Boolean::and(
            cs.namespace(|| "select ordinary step"),
            &Boolean::from(is_step_pc),
            &final_flag.not(),
        )?;
        let is_start = Boolean::from(is_start);
        enforce_boolean_sum_one(
            cs.namespace(|| "exactly one branch"),
            &[&is_start, &is_step, &is_final],
        );

        // Every branch is synthesized every time.  Muxing its input state is
        // what soundly gates all of its internal constraints, including
        // Poseidon and Schnorr, rather than trying to gate only a last check.
        let start_z = effective_state(
            cs.namespace(|| "start effective state"),
            &is_start,
            z,
            &self.start_fallback,
        )?;
        let step_z = effective_state(
            cs.namespace(|| "step effective state"),
            &is_step,
            z,
            &self.step_fallback,
        )?;
        let final_z = effective_state(
            cs.namespace(|| "final effective state"),
            &is_final,
            z,
            &self.final_fallback,
        )?;

        let start_out = synthesize_start(cs.namespace(|| "start"), &start_z, &self.start)?;
        let step_out = synthesize_step(cs.namespace(|| "step"), &step_z, &self.step)?;
        let final_out = synthesize_final(cs.namespace(|| "final"), &final_z, &self.final_witness)?;

        let pc_tail = select_num(
            cs.namespace(|| "select pc tail"),
            &is_step,
            &step_out.pc,
            &final_out.pc,
        )?;
        let pc = select_num(
            cs.namespace(|| "select pc"),
            &is_start,
            &start_out.pc,
            &pc_tail,
        )?;
        let acc_tail = select_num(
            cs.namespace(|| "select acc tail"),
            &is_step,
            &step_out.acc,
            &final_out.acc,
        )?;
        let acc = select_num(
            cs.namespace(|| "select acc"),
            &is_start,
            &start_out.acc,
            &acc_tail,
        )?;
        let out_tail = select_num(
            cs.namespace(|| "select out tail"),
            &is_step,
            &step_out.out,
            &final_out.out,
        )?;
        let out = select_num(
            cs.namespace(|| "select out"),
            &is_start,
            &start_out.out,
            &out_tail,
        )?;

        Ok(assemble_state(z, TransitionOutput { pc, acc, out }))
    }
}

/// Values that differ across the first two and final two slots of the state.
struct TransitionOutput {
    pc: AllocatedNum<F>,
    acc: AllocatedNum<F>,
    out: AllocatedNum<F>,
}

fn checked_state(z: &[AllocatedNum<F>]) -> &[AllocatedNum<F>] {
    // StepCircuit's arity is part of Nova's setup.  Do not turn a malicious
    // witness into a synthesis error: an arity mismatch is a programmer API
    // error, while field-value violations below become unsatisfied R1CS.
    assert_eq!(z.len(), STATE_ARITY, "SAR-ZK state arity is fixed at nine");
    z
}

fn assemble_state(z: &[AllocatedNum<F>], result: TransitionOutput) -> Vec<AllocatedNum<F>> {
    vec![
        result.pc,
        result.acc,
        z[PROFILE_TAG].clone(),
        z[ISSUER_KEY_COMMITMENT].clone(),
        z[LOG_ROOT].clone(),
        z[TREE_SIZE].clone(),
        z[POLICY_COMMITMENT].clone(),
        z[NULLIFIER_SCOPE].clone(),
        result.out,
    ]
}

/// Validate the public pieces on the real incoming state.  The output reuses
/// these exact variables, so no transition can alter public_bind.
fn enforce_public_bind<CS: ConstraintSystem<F>>(
    mut cs: CS,
    z: &[AllocatedNum<F>],
) -> Result<(), SynthesisError> {
    enforce_const(
        cs.namespace(|| "profile b tag"),
        &z[PROFILE_TAG],
        F::from(PROFILE_B_TAG),
    );
    let tree_bits = range_bits(cs.namespace(|| "tree size is u32"), &z[TREE_SIZE], 32)?;
    // `tree_size` is in 1..=2^31-1: bit 31 is clear and the value is nonzero.
    enforce_boolean_false(cs.namespace(|| "tree size below 2^31"), &tree_bits[31]);
    enforce_nonzero(cs.namespace(|| "tree size nonzero"), &z[TREE_SIZE])?;
    Ok(())
}

fn synthesize_start<CS: ConstraintSystem<F>>(
    mut cs: CS,
    z: &[AllocatedNum<F>],
    witness: &StartWitness,
) -> Result<TransitionOutput, SynthesisError> {
    enforce_const(cs.namespace(|| "pc start"), &z[PC], Pc::Start.field());
    enforce_const(cs.namespace(|| "initial acc zero"), &z[ACC], F::ZERO);
    enforce_const(cs.namespace(|| "initial out zero"), &z[OUT], F::ZERO);

    let policy = alloc_policy(cs.namespace(|| "policy opening"), witness.policy)?;
    enforce_policy_opening(
        cs.namespace(|| "policy commitment"),
        &policy,
        &z[POLICY_COMMITMENT],
    )?;

    let task_binding = alloc_num(cs.namespace(|| "task binding"), witness.task_binding)?;
    let rho = alloc_num(cs.namespace(|| "rho"), witness.rho)?;
    let transcript = poseidon::hash_gadget(
        cs.namespace(|| "initial transcript"),
        "SAR-ZK transcript",
        &[task_binding],
    )?;
    let zero = constant_num(cs.namespace(|| "zero"), F::ZERO)?;
    let acc = hash_acc(
        cs.namespace(|| "acc"),
        &transcript,
        &zero,
        &zero,
        &policy,
        &rho,
    )?;

    Ok(TransitionOutput {
        pc: constant_num(cs.namespace(|| "pc step"), Pc::Step.field())?,
        acc,
        out: z[OUT].clone(),
    })
}

fn synthesize_step<CS: ConstraintSystem<F>>(
    mut cs: CS,
    z: &[AllocatedNum<F>],
    witness: &StepWitness,
) -> Result<TransitionOutput, SynthesisError> {
    enforce_const(cs.namespace(|| "pc step"), &z[PC], Pc::Step.field());
    enforce_const(
        cs.namespace(|| "out remains zero before final"),
        &z[OUT],
        F::ZERO,
    );

    let opening = alloc_acc_opening(cs.namespace(|| "acc opening"), witness.opening)?;
    enforce_acc_opening(
        cs.namespace(|| "acc opening checks"),
        &opening,
        &z[ACC],
        &z[POLICY_COMMITMENT],
    )?;

    let entry = alloc_entry(cs.namespace(|| "entry"), &witness.entry)?;
    // The two digest limbs are SHA-256's 128-bit big-endian halves.  This is
    // enforced even for padding so there is never an unbounded digest slot.
    let _ = range_bits(cs.namespace(|| "digest hi 128-bit"), &entry.d_hi, 128)?;
    let _ = range_bits(cs.namespace(|| "digest lo 128-bit"), &entry.d_lo, 128)?;

    let k0 = is_equal_const(
        cs.namespace(|| "kind padding"),
        &entry.kind,
        F::from(KIND_PADDING),
    )?;
    let k1 = is_equal_const(
        cs.namespace(|| "kind tool"),
        &entry.kind,
        F::from(KIND_TOOL),
    )?;
    let k2 = is_equal_const(
        cs.namespace(|| "kind egress"),
        &entry.kind,
        F::from(KIND_EGRESS),
    )?;
    let k3 = is_equal_const(
        cs.namespace(|| "kind file"),
        &entry.kind,
        F::from(KIND_FILE),
    )?;
    let k4 = is_equal_const(
        cs.namespace(|| "kind payment"),
        &entry.kind,
        F::from(KIND_PAYMENT),
    )?;
    enforce_allocated_bit_sum_one(
        cs.namespace(|| "known entry kind"),
        &[&k0, &k1, &k2, &k3, &k4],
    );
    let _k0 = Boolean::from(k0);
    let k1 = Boolean::from(k1);
    let k2 = Boolean::from(k2);
    let k3 = Boolean::from(k3);
    let k4 = Boolean::from(k4);
    let tool_or_egress = Boolean::or(cs.namespace(|| "real tool or egress"), &k1, &k2)?;
    let file_or_payment = Boolean::or(cs.namespace(|| "real file or payment"), &k3, &k4)?;
    let is_real = Boolean::or(
        cs.namespace(|| "real entry"),
        &tool_or_egress,
        &file_or_payment,
    )?;

    // Tool membership: the path/index are semantically relevant only for a
    // tool.  We first mux the index to zero for other kinds, then gate the
    // root equality by `k1`; unrelated witness slots stay harmless.
    let zero = constant_num(cs.namespace(|| "zero"), F::ZERO)?;
    let tool_index = select_num(
        cs.namespace(|| "tool index or zero"),
        &k1,
        &entry.allow_index,
        &zero,
    )?;
    let tool_index_bits = range_bits(
        cs.namespace(|| "allow index 16-bit"),
        &tool_index,
        ALLOWLIST_DEPTH,
    )?;
    let allow_leaf = poseidon::hash_gadget(
        cs.namespace(|| "allow leaf"),
        "SAR-ZK allow",
        &[entry.d_hi.clone(), entry.d_lo.clone()],
    )?;
    let allow_root = merkle_root(
        cs.namespace(|| "allowlist path"),
        allow_leaf,
        &entry.allow_path,
        &tool_index_bits,
    )?;
    enforce_equal_gated(
        cs.namespace(|| "tool is allowlisted"),
        &k1,
        &allow_root,
        &opening.policy.allowlist_root,
    );
    enforce_const_gated(
        cs.namespace(|| "egress allowed"),
        &k2,
        &opening.policy.egress_allowed,
        F::ONE,
    );

    let next_index_for_hash = add_one(cs.namespace(|| "next transcript index"), &opening.index)?;
    let stepped_transcript = poseidon::hash_gadget(
        cs.namespace(|| "transcript step"),
        "SAR-ZK step",
        &[
            opening.transcript.clone(),
            next_index_for_hash,
            entry.kind.clone(),
            entry.d_hi.clone(),
            entry.d_lo.clone(),
        ],
    )?;
    let next_transcript = select_num(
        cs.namespace(|| "padding leaves transcript"),
        &is_real,
        &stepped_transcript,
        &opening.transcript,
    )?;
    let next_index = add_boolean(
        cs.namespace(|| "real entry increments index"),
        &opening.index,
        &is_real,
    )?;
    let next_pay_count = add_boolean(
        cs.namespace(|| "payment increments count"),
        &opening.pay_count,
        &k4,
    )?;
    // Addition happens in F, so re-range-check the outputs to rule out a
    // 2^32 wraparound in either count.
    let _ = range_bits(cs.namespace(|| "next index u32"), &next_index, 32)?;
    let _ = range_bits(cs.namespace(|| "next pay count u32"), &next_pay_count, 32)?;

    let acc = hash_acc(
        cs.namespace(|| "next acc"),
        &next_transcript,
        &next_index,
        &next_pay_count,
        &opening.policy,
        &opening.rho,
    )?;
    Ok(TransitionOutput {
        pc: constant_num(cs.namespace(|| "pc remains step"), Pc::Step.field())?,
        acc,
        out: z[OUT].clone(),
    })
}

fn synthesize_final<CS: ConstraintSystem<F>>(
    mut cs: CS,
    z: &[AllocatedNum<F>],
    witness: &FinalWitness,
) -> Result<TransitionOutput, SynthesisError> {
    enforce_const(
        cs.namespace(|| "pc step before final"),
        &z[PC],
        Pc::Step.field(),
    );
    enforce_const(
        cs.namespace(|| "out is zero before final"),
        &z[OUT],
        F::ZERO,
    );

    let opening = alloc_acc_opening(cs.namespace(|| "acc opening"), witness.opening)?;
    enforce_acc_opening(
        cs.namespace(|| "acc opening checks"),
        &opening,
        &z[ACC],
        &z[POLICY_COMMITMENT],
    )?;

    let statement = alloc_statement(cs.namespace(|| "statement"), witness.statement)?;
    enforce_const(
        cs.namespace(|| "statement profile b"),
        &statement.profile_tag,
        F::from(PROFILE_B_TAG),
    );
    enforce_equal(
        cs.namespace(|| "statement profile matches public"),
        &statement.profile_tag,
        &z[PROFILE_TAG],
    );
    let _ = range_bits(
        cs.namespace(|| "statement step count u32"),
        &statement.step_count,
        32,
    )?;
    enforce_nonzero(
        cs.namespace(|| "statement step count nonzero"),
        &statement.step_count,
    )?;
    enforce_equal(
        cs.namespace(|| "statement transcript matches acc"),
        &statement.transcript,
        &opening.transcript,
    );
    enforce_equal(
        cs.namespace(|| "statement count matches acc"),
        &statement.step_count,
        &opening.index,
    );
    assert_less_or_equal_u32(
        cs.namespace(|| "payment count bounded"),
        &opening.pay_count,
        &opening.policy.payment_bound,
    )?;

    let statement_hash = hash_statement(cs.namespace(|| "statement hash"), &statement)?;
    let pk = schnorr::alloc_point(cs.namespace(|| "issuer public key"), witness.issuer_pk)?;
    let issuer_commitment = poseidon::hash_gadget(
        cs.namespace(|| "issuer key commitment"),
        "SAR-ZK issuer",
        &[pk.x.clone(), pk.y.clone()],
    )?;
    enforce_equal(
        cs.namespace(|| "pinned issuer key commitment"),
        &issuer_commitment,
        &z[ISSUER_KEY_COMMITMENT],
    );
    let r_point = schnorr::alloc_point(cs.namespace(|| "signature R"), witness.signature.r)?;
    let s_bits =
        schnorr::alloc_scalar_bits(cs.namespace(|| "signature s bits"), witness.signature.s)?;
    schnorr::verify_gadget(
        cs.namespace(|| "issuer schnorr signature"),
        &pk,
        &r_point,
        &s_bits,
        &statement_hash,
    )?;

    let nk = alloc_num(cs.namespace(|| "nk"), witness.nk)?;
    let r = alloc_num(cs.namespace(|| "nk opening r"), witness.r)?;
    let nk_commitment = poseidon::hash_gadget(
        cs.namespace(|| "nk commitment"),
        "SAR-ZK nk",
        &[nk.clone(), r],
    )?;
    enforce_equal(
        cs.namespace(|| "nk opening"),
        &nk_commitment,
        &statement.nk_commitment,
    );

    let leaf = poseidon::hash_gadget(
        cs.namespace(|| "statement leaf"),
        "SAR-ZK leaf",
        &[statement_hash],
    )?;
    let leaf_index = alloc_num(cs.namespace(|| "leaf index"), witness.leaf_index)?;
    let leaf_index_bits = range_bits(cs.namespace(|| "leaf index u32"), &leaf_index, 32)?;
    assert_less_than_u32(
        cs.namespace(|| "leaf index below tree size"),
        &leaf_index,
        &z[TREE_SIZE],
    )?;
    let log_path = alloc_path(cs.namespace(|| "log path"), &witness.log_path)?;
    let computed_root = merkle_root(
        cs.namespace(|| "log membership"),
        leaf,
        &log_path,
        &leaf_index_bits,
    )?;
    enforce_equal(cs.namespace(|| "log root"), &computed_root, &z[LOG_ROOT]);

    let nullifier = poseidon::hash_gadget(
        cs.namespace(|| "nullifier"),
        "SAR-ZK nullifier",
        &[nk, z[NULLIFIER_SCOPE].clone()],
    )?;
    Ok(TransitionOutput {
        pc: constant_num(cs.namespace(|| "pc halt"), Pc::Halt.field())?,
        acc: constant_num(cs.namespace(|| "clear acc"), F::ZERO)?,
        out: nullifier,
    })
}

// -------------------------------------------------------------------------
// Gadget composition and low-level constraints.

struct AllocPolicy {
    allowlist_root: AllocatedNum<F>,
    egress_allowed: AllocatedNum<F>,
    payment_bound: AllocatedNum<F>,
}

struct AllocAccOpening {
    transcript: AllocatedNum<F>,
    index: AllocatedNum<F>,
    pay_count: AllocatedNum<F>,
    policy: AllocPolicy,
    rho: AllocatedNum<F>,
}

struct AllocEntry {
    kind: AllocatedNum<F>,
    d_hi: AllocatedNum<F>,
    d_lo: AllocatedNum<F>,
    allow_index: AllocatedNum<F>,
    allow_path: [AllocatedNum<F>; ALLOWLIST_DEPTH],
}

struct AllocStatement {
    profile_tag: AllocatedNum<F>,
    task_binding: AllocatedNum<F>,
    step_count: AllocatedNum<F>,
    transcript: AllocatedNum<F>,
    nk_commitment: AllocatedNum<F>,
}

fn alloc_num<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: F,
) -> Result<AllocatedNum<F>, SynthesisError> {
    AllocatedNum::alloc(cs.namespace(|| "witness"), || Ok(value))
}

fn constant_num<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: F,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let n = AllocatedNum::alloc(cs.namespace(|| "constant"), || Ok(value))?;
    enforce_const(cs.namespace(|| "constant constraint"), &n, value);
    Ok(n)
}

fn alloc_policy<CS: ConstraintSystem<F>>(
    mut cs: CS,
    policy: PolicyOpening,
) -> Result<AllocPolicy, SynthesisError> {
    Ok(AllocPolicy {
        allowlist_root: alloc_num(cs.namespace(|| "allowlist root"), policy.allowlist_root)?,
        egress_allowed: alloc_num(cs.namespace(|| "egress allowed"), policy.egress_allowed)?,
        payment_bound: alloc_num(cs.namespace(|| "payment bound"), policy.payment_bound)?,
    })
}

fn alloc_acc_opening<CS: ConstraintSystem<F>>(
    mut cs: CS,
    opening: AccOpening,
) -> Result<AllocAccOpening, SynthesisError> {
    Ok(AllocAccOpening {
        transcript: alloc_num(cs.namespace(|| "transcript"), opening.transcript)?,
        index: alloc_num(cs.namespace(|| "index"), opening.index)?,
        pay_count: alloc_num(cs.namespace(|| "pay count"), opening.pay_count)?,
        policy: alloc_policy(cs.namespace(|| "policy"), opening.policy)?,
        rho: alloc_num(cs.namespace(|| "rho"), opening.rho)?,
    })
}

fn alloc_entry<CS: ConstraintSystem<F>>(
    mut cs: CS,
    entry: &EntryWitness,
) -> Result<AllocEntry, SynthesisError> {
    let mut path_values = Vec::with_capacity(ALLOWLIST_DEPTH);
    for (i, value) in entry.allow_path.iter().enumerate() {
        path_values.push(alloc_num(
            cs.namespace(|| format!("allow path {i}")),
            *value,
        )?);
    }
    let path: [AllocatedNum<F>; ALLOWLIST_DEPTH] = path_values.try_into().map_err(|_| {
        SynthesisError::IncompatibleLengthVector("allow path must have depth 16".to_owned())
    })?;
    Ok(AllocEntry {
        kind: alloc_num(cs.namespace(|| "kind"), entry.kind)?,
        d_hi: alloc_num(cs.namespace(|| "digest hi"), entry.d_hi)?,
        d_lo: alloc_num(cs.namespace(|| "digest lo"), entry.d_lo)?,
        allow_index: alloc_num(cs.namespace(|| "allow index"), entry.allow_index)?,
        allow_path: path,
    })
}

fn alloc_statement<CS: ConstraintSystem<F>>(
    mut cs: CS,
    statement: StatementWitness,
) -> Result<AllocStatement, SynthesisError> {
    Ok(AllocStatement {
        profile_tag: alloc_num(cs.namespace(|| "profile tag"), statement.profile_tag)?,
        task_binding: alloc_num(cs.namespace(|| "task binding"), statement.task_binding)?,
        step_count: alloc_num(cs.namespace(|| "step count"), statement.step_count)?,
        transcript: alloc_num(cs.namespace(|| "transcript"), statement.transcript)?,
        nk_commitment: alloc_num(cs.namespace(|| "nk commitment"), statement.nk_commitment)?,
    })
}

fn alloc_path<CS: ConstraintSystem<F>, const N: usize>(
    mut cs: CS,
    path: &[F; N],
) -> Result<[AllocatedNum<F>; N], SynthesisError> {
    let mut values = Vec::with_capacity(N);
    for (i, value) in path.iter().enumerate() {
        values.push(alloc_num(cs.namespace(|| format!("path {i}")), *value)?);
    }
    values.try_into().map_err(|_| {
        SynthesisError::IncompatibleLengthVector(
            "Merkle path length changed during allocation".to_owned(),
        )
    })
}

fn enforce_policy_opening<CS: ConstraintSystem<F>>(
    mut cs: CS,
    policy: &AllocPolicy,
    expected_commitment: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let egress = boolean_num(cs.namespace(|| "egress is bit"), &policy.egress_allowed)?;
    // Keep the explicitly checked boolean alive.  `boolean_num` returns a
    // Boolean wrapper; assigning it avoids a misleading "host bool" path.
    let _ = egress;
    let _ = range_bits(
        cs.namespace(|| "payment bound u32"),
        &policy.payment_bound,
        32,
    )?;
    let commitment = poseidon::hash_gadget(
        cs.namespace(|| "policy hash"),
        "SAR-ZK policy",
        &[
            policy.allowlist_root.clone(),
            policy.egress_allowed.clone(),
            policy.payment_bound.clone(),
        ],
    )?;
    enforce_equal(
        cs.namespace(|| "policy binds public"),
        &commitment,
        expected_commitment,
    );
    Ok(())
}

fn enforce_acc_opening<CS: ConstraintSystem<F>>(
    mut cs: CS,
    opening: &AllocAccOpening,
    expected_acc: &AllocatedNum<F>,
    expected_policy: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let _ = range_bits(cs.namespace(|| "index u32"), &opening.index, 32)?;
    let _ = range_bits(cs.namespace(|| "pay count u32"), &opening.pay_count, 32)?;
    enforce_policy_opening(cs.namespace(|| "policy"), &opening.policy, expected_policy)?;
    let acc = hash_acc(
        cs.namespace(|| "recompute acc"),
        &opening.transcript,
        &opening.index,
        &opening.pay_count,
        &opening.policy,
        &opening.rho,
    )?;
    enforce_equal(
        cs.namespace(|| "acc opening matches state"),
        &acc,
        expected_acc,
    );
    Ok(())
}

fn hash_acc<CS: ConstraintSystem<F>>(
    mut cs: CS,
    transcript: &AllocatedNum<F>,
    index: &AllocatedNum<F>,
    pay_count: &AllocatedNum<F>,
    policy: &AllocPolicy,
    rho: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    poseidon::hash_gadget(
        cs.namespace(|| "SAR-ZK acc"),
        "SAR-ZK acc",
        &[
            transcript.clone(),
            index.clone(),
            pay_count.clone(),
            policy.allowlist_root.clone(),
            policy.egress_allowed.clone(),
            policy.payment_bound.clone(),
            rho.clone(),
        ],
    )
}

fn hash_statement<CS: ConstraintSystem<F>>(
    mut cs: CS,
    statement: &AllocStatement,
) -> Result<AllocatedNum<F>, SynthesisError> {
    poseidon::hash_gadget(
        cs.namespace(|| "SAR-ZK statement"),
        "SAR-ZK statement",
        &[
            statement.profile_tag.clone(),
            statement.task_binding.clone(),
            statement.step_count.clone(),
            statement.transcript.clone(),
            statement.nk_commitment.clone(),
        ],
    )
}

fn merkle_root<CS: ConstraintSystem<F>, const N: usize>(
    mut cs: CS,
    mut node: AllocatedNum<F>,
    path: &[AllocatedNum<F>; N],
    index_bits: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError> {
    assert_eq!(
        index_bits.len(),
        N,
        "Merkle index width must match path depth"
    );
    for (level, (sibling, bit)) in path.iter().zip(index_bits).enumerate() {
        let (left, right) = AllocatedNum::conditionally_reverse(
            cs.namespace(|| format!("path direction {level}")),
            &node,
            sibling,
            bit,
        )?;
        node = poseidon::hash_gadget(
            cs.namespace(|| format!("node {level}")),
            "SAR-ZK node",
            &[left, right],
        )?;
    }
    Ok(node)
}

fn effective_state<CS: ConstraintSystem<F>>(
    mut cs: CS,
    selected: &Boolean,
    actual: &[AllocatedNum<F>],
    fallback: &State,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    actual
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let fallback = alloc_num(cs.namespace(|| format!("fallback {i}")), fallback[i])?;
            select_num(
                cs.namespace(|| format!("state mux {i}")),
                selected,
                n,
                &fallback,
            )
        })
        .collect()
}

fn select_num<CS: ConstraintSystem<F>>(
    mut cs: CS,
    condition: &Boolean,
    when_true: &AllocatedNum<F>,
    when_false: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "selected value"), || {
        match (
            condition.get_value(),
            when_true.get_value(),
            when_false.get_value(),
        ) {
            (Some(true), Some(v), _) => Ok(v),
            (Some(false), _, Some(v)) => Ok(v),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    // condition * (true - false) = result - false
    cs.enforce(
        || "conditional selection",
        |lc| lc + when_true.get_variable() - when_false.get_variable(),
        |_| condition.lc(CS::one(), F::ONE),
        |lc| lc + result.get_variable() - when_false.get_variable(),
    );
    Ok(result)
}

fn add_one<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "sum"), || {
        a.get_value()
            .map(|v| v + F::ONE)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "add one",
        |lc| lc + a.get_variable() + CS::one(),
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

fn add_boolean<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let result = AllocatedNum::alloc(cs.namespace(|| "sum"), || {
        match (a.get_value(), b.get_value()) {
            (Some(mut a), Some(true)) => {
                a += F::ONE;
                Ok(a)
            }
            (Some(a), Some(false)) => Ok(a),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    cs.enforce(
        || "add boolean",
        |lc| lc + a.get_variable() + &b.lc(CS::one(), F::ONE),
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

/// Constrain an allocated field element to be exactly zero or one and return a
/// Boolean view of the same variable.  For malformed assignments the Boolean
/// witness value is irrelevant because the preceding R1CS constraint fails.
fn boolean_num<CS: ConstraintSystem<F>>(
    mut cs: CS,
    n: &AllocatedNum<F>,
) -> Result<Boolean, SynthesisError> {
    let bit = alloc_bit_from_num(cs.namespace(|| "boolean copy"), n)?;
    cs.enforce(
        || "boolean copy equals field element",
        |lc| lc + bit.get_variable() - n.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(Boolean::from(bit))
}

/// Returns a sound equality bit without division-by-zero synthesis errors.
/// Both equations force `equal = 1` exactly when `a == constant`.
fn is_equal_const<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    constant: F,
) -> Result<AllocatedBit, SynthesisError> {
    let equal = alloc_bit_from_predicate(cs.namespace(|| "equal bit"), a, move |value| {
        value == constant
    })?;
    let inverse = AllocatedNum::alloc(cs.namespace(|| "difference inverse"), || {
        let difference = a.get_value().ok_or(SynthesisError::AssignmentMissing)? - constant;
        Ok(difference.invert().unwrap_or(F::ZERO))
    })?;
    // (a-c) * equal = 0
    cs.enforce(
        || "equal implies zero difference",
        |lc| lc + a.get_variable() + (-constant, CS::one()),
        |lc| lc + equal.get_variable(),
        |lc| lc,
    );
    // (a-c) * inverse = 1-equal
    cs.enforce(
        || "nonzero difference implies unequal",
        |lc| lc + a.get_variable() + (-constant, CS::one()),
        |lc| lc + inverse.get_variable(),
        |lc| lc + CS::one() - equal.get_variable(),
    );
    Ok(equal)
}

fn enforce_equal<CS: ConstraintSystem<F>>(mut cs: CS, a: &AllocatedNum<F>, b: &AllocatedNum<F>) {
    cs.enforce(
        || "equality",
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

fn enforce_const<CS: ConstraintSystem<F>>(mut cs: CS, a: &AllocatedNum<F>, constant: F) {
    cs.enforce(
        || "constant equality",
        |lc| lc + a.get_variable() + (-constant, CS::one()),
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

fn enforce_equal_gated<CS: ConstraintSystem<F>>(
    mut cs: CS,
    enabled: &Boolean,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) {
    cs.enforce(
        || "gated equality",
        |lc| lc + a.get_variable() - b.get_variable(),
        |_| enabled.lc(CS::one(), F::ONE),
        |lc| lc,
    );
}

fn enforce_const_gated<CS: ConstraintSystem<F>>(
    mut cs: CS,
    enabled: &Boolean,
    a: &AllocatedNum<F>,
    constant: F,
) {
    cs.enforce(
        || "gated constant equality",
        |lc| lc + a.get_variable() + (-constant, CS::one()),
        |_| enabled.lc(CS::one(), F::ONE),
        |lc| lc,
    );
}

fn enforce_boolean_false<CS: ConstraintSystem<F>>(mut cs: CS, b: &Boolean) {
    cs.enforce(
        || "boolean false",
        |_| b.lc(CS::one(), F::ONE),
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

fn enforce_allocated_bit_sum_one<CS: ConstraintSystem<F>>(mut cs: CS, bits: &[&AllocatedBit]) {
    cs.enforce(
        || "boolean sum is one",
        |lc| {
            let mut lc = lc - CS::one();
            for bit in bits {
                lc = lc + bit.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

fn enforce_boolean_sum_one<CS: ConstraintSystem<F>>(mut cs: CS, bits: &[&Boolean]) {
    cs.enforce(
        || "boolean sum is one",
        |lc| {
            let mut lc = lc - CS::one();
            for bit in bits {
                lc = lc + &bit.lc(CS::one(), F::ONE);
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
}

/// Decompose `n` into exactly `width` boolean bits and pack them back into
/// `n`.  Every width used here is at most 128, hence the packed integer is
/// strictly below the Pallas modulus; equality in F is therefore an injective
/// integer range check, not a host-side comparison or modular shortcut.
fn range_bits<CS: ConstraintSystem<F>>(
    mut cs: CS,
    n: &AllocatedNum<F>,
    width: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
    assert!(width <= 128, "SAR-ZK only range-checks values below 2^128");
    let mut bits = Vec::with_capacity(width);
    for i in 0..width {
        let bit = alloc_bit_from_predicate(cs.namespace(|| format!("bit {i}")), n, move |value| {
            let repr = value.to_repr();
            (repr.as_ref()[i / 8] >> (i % 8)) & 1 == 1
        })?;
        bits.push(Boolean::from(bit));
    }
    cs.enforce(
        || "range packing",
        |lc| {
            let mut lc = lc - n.get_variable();
            let mut coefficient = F::ONE;
            for bit in &bits {
                lc = lc + &bit.lc(CS::one(), coefficient);
                coefficient = coefficient.double();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(bits)
}

/// Allocate a boolean whose assignment is a predicate of an existing field
/// witness.  Reading the source assignment happens only inside `CS::alloc`'s
/// closure, so `ShapeCS` sees the same circuit without an assignment.
fn alloc_bit_from_predicate<CS: ConstraintSystem<F>, P: FnOnce(F) -> bool>(
    mut cs: CS,
    source: &AllocatedNum<F>,
    predicate: P,
) -> Result<AllocatedBit, SynthesisError> {
    let mut witnessed = None;
    let variable = cs.alloc(
        || "derived bit",
        || {
            let bit = predicate(
                source
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?,
            );
            witnessed = Some(bit);
            Ok(if bit { F::ONE } else { F::ZERO })
        },
    )?;
    cs.enforce(
        || "derived bit is boolean",
        |lc| lc + variable,
        |lc| lc + CS::one() - variable,
        |lc| lc,
    );
    Ok(AllocatedBit::from_parts_unchecked(variable, witnessed))
}

fn alloc_bit_from_num<CS: ConstraintSystem<F>>(
    cs: CS,
    source: &AllocatedNum<F>,
) -> Result<AllocatedBit, SynthesisError> {
    alloc_bit_from_predicate(cs, source, |value| value == F::ONE)
}

fn enforce_nonzero<CS: ConstraintSystem<F>>(
    mut cs: CS,
    n: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let zero = is_equal_const(cs.namespace(|| "is zero"), n, F::ZERO)?;
    enforce_boolean_false(cs.namespace(|| "not zero"), &Boolean::from(zero));
    Ok(())
}

/// Enforce `a < b`, where both are canonical 32-bit values.
fn assert_less_than_u32<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let _ = range_bits(cs.namespace(|| "left u32"), a, 32)?;
    let _ = range_bits(cs.namespace(|| "right u32"), b, 32)?;
    let two32 = F::from(1u64 << 32);
    let difference = AllocatedNum::alloc(cs.namespace(|| "borrow encoding"), || {
        match (a.get_value(), b.get_value()) {
            (Some(a), Some(b)) => Ok(a + two32 - b),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    // d = a + 2^32 - b.  Its bit 32 is zero iff a < b.
    cs.enforce(
        || "borrow encoding equality",
        |lc| lc + a.get_variable() + (two32, CS::one()) - b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + difference.get_variable(),
    );
    let bits = range_bits(cs.namespace(|| "borrow encoding 33-bit"), &difference, 33)?;
    enforce_boolean_false(cs.namespace(|| "strictly below"), &bits[32]);
    Ok(())
}

/// Enforce `a <= b`, where both are canonical 32-bit values.
fn assert_less_or_equal_u32<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) -> Result<(), SynthesisError> {
    let _ = range_bits(cs.namespace(|| "left u32"), a, 32)?;
    let _ = range_bits(cs.namespace(|| "right u32"), b, 32)?;
    let two32 = F::from(1u64 << 32);
    let difference = AllocatedNum::alloc(cs.namespace(|| "no borrow encoding"), || {
        match (a.get_value(), b.get_value()) {
            (Some(a), Some(b)) => Ok(b + two32 - a),
            _ => Err(SynthesisError::AssignmentMissing),
        }
    })?;
    // d = b + 2^32 - a.  Its bit 32 is one iff a <= b.
    cs.enforce(
        || "no borrow encoding equality",
        |lc| lc + b.get_variable() + (two32, CS::one()) - a.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + difference.get_variable(),
    );
    let bits = range_bits(
        cs.namespace(|| "no borrow encoding 33-bit"),
        &difference,
        33,
    )?;
    enforce_boolean_false(cs.namespace(|| "top bit is one"), &bits[32].not());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{issuance::Fixture, proofs, E1};
    use ff::Field;
    use nova_snark::frontend::shape_cs::ShapeCS;

    fn check_part(cs: &ShapeCS<E1>, name: &str, before: usize, expected: usize) -> usize {
        let measured = cs.num_constraints() - before;
        println!("{name:<36} {measured:>6}");
        assert_eq!(measured, expected, "unexpected constraint count for {name}");
        measured
    }

    #[test]
    fn uniform_constraint_count_is_explained_part_by_part() {
        let fixture = Fixture::benchmark_deterministic(1, 1, 0, 0x5341_522d_5a4b).unwrap();
        let uniform = fixture.uniform_steps().remove(0).circuit;
        let branches = fixture.branch_steps_unpadded();
        let standalone_counts = branches
            .iter()
            .map(|step| proofs::constraint_count(&step.circuit))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(standalone_counts, vec![2_483, 12_806, 45_046]);
        let uniform_count = proofs::constraint_count(&uniform).unwrap();
        assert_eq!(uniform_count, 60_301);

        let mut cs = ShapeCS::<E1>::new();
        let z = (0..STATE_ARITY)
            .map(|index| {
                AllocatedNum::alloc(cs.namespace(|| format!("state_{index}")), || Ok(F::ZERO))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        println!("part                                   constraints");
        macro_rules! part {
            ($name:literal, $expected:expr, $body:expr) => {{
                let before = cs.num_constraints();
                let result = $body;
                let measured = check_part(&cs, $name, before, $expected);
                (result, measured)
            }};
        }

        let ((), public_bind) = part!(
            "enforce_public_bind",
            39,
            enforce_public_bind(cs.namespace(|| "public bind"), &z).unwrap()
        );
        let (is_start, pc_start_check) = part!(
            "pc equals START",
            3,
            is_equal_const(cs.namespace(|| "pc is start"), &z[PC], Pc::Start.field()).unwrap()
        );
        let (is_step_pc, pc_step_check) = part!(
            "pc equals STEP",
            3,
            is_equal_const(cs.namespace(|| "pc is step"), &z[PC], Pc::Step.field()).unwrap()
        );
        let ((), pc_sum_one) = part!(
            "recognized pc sum one",
            1,
            enforce_allocated_bit_sum_one(
                cs.namespace(|| "pc is recognized"),
                &[&is_start, &is_step_pc],
            )
        );
        let (final_flag, final_flag_count) = part!("final flag", 1, {
            let bit = AllocatedBit::alloc(
                cs.namespace(|| "final flag"),
                Some(uniform.final_flag),
            )
            .unwrap();
            Boolean::from(bit)
        });
        let (is_final, select_final_and) = part!(
            "select final AND",
            1,
            Boolean::and(
                cs.namespace(|| "select final"),
                &Boolean::from(is_step_pc.clone()),
                &final_flag,
            )
            .unwrap()
        );
        let (is_step, select_step_and) = part!(
            "select ordinary step AND",
            1,
            Boolean::and(
                cs.namespace(|| "select ordinary step"),
                &Boolean::from(is_step_pc),
                &final_flag.not(),
            )
            .unwrap()
        );
        let is_start = Boolean::from(is_start);
        let ((), branch_sum_one) = part!(
            "branch sum one",
            1,
            enforce_boolean_sum_one(
                cs.namespace(|| "exactly one branch"),
                &[&is_start, &is_step, &is_final],
            )
        );

        let (start_z, start_effective_state) = part!(
            "start effective state",
            9,
            effective_state(
                cs.namespace(|| "start effective state"),
                &is_start,
                &z,
                &uniform.start_fallback,
            )
            .unwrap()
        );
        let (step_z, step_effective_state) = part!(
            "step effective state",
            9,
            effective_state(
                cs.namespace(|| "step effective state"),
                &is_step,
                &z,
                &uniform.step_fallback,
            )
            .unwrap()
        );
        let (final_z, final_effective_state) = part!(
            "final effective state",
            9,
            effective_state(
                cs.namespace(|| "final effective state"),
                &is_final,
                &z,
                &uniform.final_fallback,
            )
            .unwrap()
        );

        let (start_out, start_body) = part!(
            "synthesize_start without public bind",
            2_444,
            synthesize_start(cs.namespace(|| "start"), &start_z, &uniform.start).unwrap()
        );
        let (step_out, step_body) = part!(
            "synthesize_step without public bind",
            12_767,
            synthesize_step(cs.namespace(|| "step"), &step_z, &uniform.step).unwrap()
        );
        let (final_out, final_body) = part!(
            "synthesize_final without public bind",
            45_007,
            synthesize_final(
                cs.namespace(|| "final"),
                &final_z,
                &uniform.final_witness,
            )
            .unwrap()
        );

        let (pc_tail, select_pc_tail) = part!(
            "select pc tail",
            1,
            select_num(
                cs.namespace(|| "select pc tail"),
                &is_step,
                &step_out.pc,
                &final_out.pc,
            )
            .unwrap()
        );
        let (_pc, select_pc) = part!(
            "select pc",
            1,
            select_num(
                cs.namespace(|| "select pc"),
                &is_start,
                &start_out.pc,
                &pc_tail,
            )
            .unwrap()
        );
        let (acc_tail, select_acc_tail) = part!(
            "select acc tail",
            1,
            select_num(
                cs.namespace(|| "select acc tail"),
                &is_step,
                &step_out.acc,
                &final_out.acc,
            )
            .unwrap()
        );
        let (_acc, select_acc) = part!(
            "select acc",
            1,
            select_num(
                cs.namespace(|| "select acc"),
                &is_start,
                &start_out.acc,
                &acc_tail,
            )
            .unwrap()
        );
        let (out_tail, select_out_tail) = part!(
            "select out tail",
            1,
            select_num(
                cs.namespace(|| "select out tail"),
                &is_step,
                &step_out.out,
                &final_out.out,
            )
            .unwrap()
        );
        let (_out, select_out) = part!(
            "select out",
            1,
            select_num(
                cs.namespace(|| "select out"),
                &is_start,
                &start_out.out,
                &out_tail,
            )
            .unwrap()
        );

        let selector_count = pc_start_check
            + pc_step_check
            + pc_sum_one
            + final_flag_count
            + select_final_and
            + select_step_and
            + branch_sum_one
            + start_effective_state
            + step_effective_state
            + final_effective_state
            + select_pc_tail
            + select_pc
            + select_acc_tail
            + select_acc
            + select_out_tail
            + select_out;
        assert_eq!(selector_count, 44);

        assert_eq!(public_bind + start_body, 2_483);
        assert_eq!(public_bind + step_body, 12_806);
        assert_eq!(public_bind + final_body, 45_046);
        assert_eq!(standalone_counts[0], public_bind + start_body);
        assert_eq!(standalone_counts[1], public_bind + step_body);
        assert_eq!(standalone_counts[2], public_bind + final_body);

        let parts_total = public_bind + start_body + step_body + final_body + selector_count;
        assert_eq!(parts_total, 60_301);
        assert_eq!(cs.num_constraints(), parts_total);
        assert_eq!(uniform_count, parts_total);
        assert_eq!(2 * public_bind - selector_count, 34);
        assert_eq!(
            standalone_counts.iter().sum::<usize>() - uniform_count,
            2 * public_bind - selector_count
        );

        println!("{:<36} {:>6}", "selector logic total", selector_count);
        println!("{:<36} {:>6}", "uniform parts total", parts_total);
        println!("{:<36} {:>6}", "standalone sum minus uniform", 34);
    }
}
