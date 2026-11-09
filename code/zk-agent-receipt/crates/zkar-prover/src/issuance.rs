//! Native issuance for SAR-ZK profile b fixtures and benchmarks.
//!
//! [`Fixture::random`] makes nondeterministic *synthetic* issuance with a
//! caller-supplied CSPRNG; [`Fixture::benchmark_deterministic`] exists only
//! for the paper's recorded benchmark fixtures. Real deployments should use
//! their own issuer key custody and signing workflow. This module computes
//! native statements, signatures, paths, and known state traces. It does not
//! decide whether a proof is valid—the corresponding constraints live in
//! `relation.rs`.

use crate::{
    poseidon,
    relation::{
        allow_leaf_native, final_output_native, issuer_key_commitment_native, log_leaf_native,
        nk_commitment_native, nullifier_native, policy_commitment_native, start_output_native,
        statement_hash_native, step_output_native, transcript_start_native, transcript_step_native,
        AccOpening, Branch, BranchCircuit, EntryWitness, FinalWitness, PolicyOpening, PublicBind,
        StartWitness, State, StatementWitness, StepWitness, TraceStep, UniformCircuit,
        ALLOWLIST_DEPTH, KIND_EGRESS, KIND_FILE, KIND_PADDING, KIND_PAYMENT, KIND_TOOL, LOG_DEPTH,
        MAX_TREE_SIZE, PROFILE_B_TAG,
    },
    schnorr, F,
};
use ff::Field;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zkar_circuit::{FieldElement, FieldHasher};

/// Thin adapter that reuses the off-circuit fixed-depth tree builder
/// with the actual profile Poseidon, rather than duplicating tree semantics in
/// the issuance path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeField(F);

impl FieldElement for NativeField {
    fn from_u64(value: u64) -> Self {
        Self(F::from(value))
    }

    fn from_be_bytes16(bytes: &[u8; 16]) -> Self {
        Self(bytes.iter().fold(F::ZERO, |value, byte| {
            value * F::from(256) + F::from(*byte as u64)
        }))
    }
}

struct NativeHasher;

impl FieldHasher for NativeHasher {
    type F = NativeField;

    fn hash(domain: &'static str, input: &[Self::F]) -> Self::F {
        NativeField(poseidon::hash_native(
            domain,
            &input.iter().map(|value| value.0).collect::<Vec<_>>(),
        ))
    }
}

/// Errors from native fixture issuance.  These are caller/configuration
/// errors, not a substitute for any in-circuit adversarial validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssuanceError {
    ZeroSteps,
    TooManySteps,
    EmptyLog,
    LogTooLarge,
    LeafIndexOutOfRange,
    PaddingBucketOverflow,
}

impl std::fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroSteps => "step count must be at least one",
            Self::TooManySteps => "step count must be below 2^32",
            Self::EmptyLog => "log must have at least one occupied leaf",
            Self::LogTooLarge => "log tree_size must be at most 2147483647",
            Self::LeafIndexOutOfRange => "target leaf index must be below log size",
            Self::PaddingBucketOverflow => "padding bucket does not fit usize",
        };
        f.write_str(message)
    }
}

impl std::error::Error for IssuanceError {}

/// A fully issued synthetic record plus the known states needed by each proof
/// system.  Its public metadata is intentionally explicit so benchmark output
/// can report the log size and candidate-set qualification accurately.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub public_bind: PublicBind,
    pub nullifier: F,
    pub statement: StatementWitness,
    pub issuer_pk: schnorr::PallasPoint,
    pub signature: schnorr::Signature,
    pub entries: Vec<EntryWitness>,
    pub start: StartWitness,
    pub final_witness: FinalWitness,
    pub rho: F,
    pub nk: F,
    pub r: F,
    /// Occupied leaves in this synthetic log.
    pub log_leaves: usize,
    /// All generated leaves carry valid same-policy/same-bucket statements;
    /// this is a fixture candidate-set count, not a deployment anonymity claim.
    pub candidate_set_size: usize,
    pub padding_steps: usize,
    step_witnesses: Vec<StepWitness>,
    start_state: State,
    pre_final_state: State,
}

impl Fixture {
    /// Deterministic issuance for recorded benchmark/test fixtures only.
    pub fn benchmark_deterministic(
        t: usize,
        n: usize,
        index: usize,
        seed: u64,
    ) -> Result<Self, IssuanceError> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Self::random(t, n, index, &mut rng)
    }

    /// Issue a synthetic profile-b receipt with fresh `rho`, `nk`, `r`,
    /// signing key, and per-signature nonce from the caller's CSPRNG.
    ///
    /// `t` is the real inventory length. `n` is independent log occupancy,
    /// and `index` selects the target's leaf position.
    pub fn random<R: RngCore + CryptoRng>(
        t: usize,
        n: usize,
        index: usize,
        rng: &mut R,
    ) -> Result<Self, IssuanceError> {
        validate_shape(t, n, index)?;
        let padded_total = t
            .checked_add(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(IssuanceError::PaddingBucketOverflow)?;
        let padding_steps = padded_total - (t + 2);

        // A one-digest sorted, duplicate-free allowlist is canonical by
        // construction. Every generated tool entry uses this digest.
        let tool_digest = (random_limb(rng), random_limb(rng));
        let allow_leaf = allow_leaf_native(tool_digest.0, tool_digest.1);
        let (allow_root, allow_path) = tree_root_and_path(&[allow_leaf], 0, ALLOWLIST_DEPTH);
        let allow_path: [F; ALLOWLIST_DEPTH] = vec_to_array(allow_path);
        let policy = PolicyOpening {
            allowlist_root: allow_root,
            // Egress is deliberately allowed: the benchmark relation covers
            // the positive egress branch as well as its rejection tests.
            egress_allowed: F::ONE,
            payment_bound: F::from(t as u64),
        };

        let issuer_secret = schnorr::keygen(&mut *rng);
        let issuer_pk = schnorr::public_key(issuer_secret);
        let issuer_key_commitment = issuer_key_commitment_native(issuer_pk);

        let target = issue_record(t, tool_digest, allow_path, issuer_secret, rng);

        // Every occupied position gets a genuinely signed synthetic statement
        // under the same issuer, policy shape and run bucket. This avoids
        // presenting arbitrary filler field elements as a known candidate set.
        let mut leaves = Vec::with_capacity(n);
        for position in 0..n {
            if position == index {
                leaves.push(log_leaf_native(statement_hash_native(target.statement)));
            } else {
                let decoy = issue_record(t, tool_digest, allow_path, issuer_secret, rng);
                leaves.push(log_leaf_native(statement_hash_native(decoy.statement)));
            }
        }
        let (log_root, log_path) = tree_root_and_path(&leaves, index, LOG_DEPTH);
        let log_path: [F; LOG_DEPTH] = vec_to_array(log_path);

        let nullifier_scope = F::random(&mut *rng);
        let public_bind = PublicBind {
            profile_tag: F::from(PROFILE_B_TAG),
            issuer_key_commitment,
            log_root,
            tree_size: F::from(n as u64),
            policy_commitment: policy_commitment_native(policy),
            nullifier_scope,
        };
        let nullifier = nullifier_native(target.nk, nullifier_scope);
        let rho = F::random(&mut *rng);
        let start = StartWitness {
            task_binding: target.statement.task_binding,
            policy,
            rho,
        };
        let start_state = public_bind.initial_state();
        let mut current_state = start_output_native(public_bind, &start);
        let mut opening = AccOpening {
            transcript: transcript_start_native(start.task_binding),
            index: F::ZERO,
            pay_count: F::ZERO,
            policy,
            rho,
        };
        let mut step_witnesses = Vec::with_capacity(t);
        for entry in &target.entries {
            let step = StepWitness {
                opening,
                entry: entry.clone(),
            };
            current_state = step_output_native(current_state, &step);
            opening = advance_opening(opening, entry);
            step_witnesses.push(step);
        }
        let pre_final_state = current_state;
        let final_witness = FinalWitness {
            opening,
            statement: target.statement,
            issuer_pk,
            signature: target.signature,
            log_path,
            leaf_index: F::from(index as u64),
            nk: target.nk,
            r: target.r,
        };

        Ok(Self {
            public_bind,
            nullifier,
            statement: target.statement,
            issuer_pk,
            signature: target.signature,
            entries: target.entries,
            start,
            final_witness,
            rho,
            nk: target.nk,
            r: target.r,
            log_leaves: n,
            candidate_set_size: n,
            padding_steps,
            step_witnesses,
            start_state,
            pre_final_state,
        })
    }

    pub fn initial_state(&self) -> State {
        // Derive from public_bind rather than returning a hidden cache, so a
        // caller deliberately constructing a hostile public state does not
        // accidentally receive stale metadata. `start_state` remains the
        // known-valid fallback used inside uniform candidate muxes.
        self.public_bind.initial_state()
    }

    pub fn expected_final_state(&self) -> State {
        final_output_native(self.public_bind, self.nk)
    }

    /// Full padded fixed-shape trace: start, every real entry, padding up to
    /// `next_power_of_two(T + 2)`, then final.
    pub fn uniform_steps(&self) -> Vec<TraceStep<UniformCircuit>> {
        let mut trace = Vec::with_capacity(self.entries.len() + self.padding_steps + 2);
        let fallback = self.fallbacks();
        let mut input = self.start_state;

        let start_circuit = UniformCircuit {
            final_flag: false,
            start: self.start.clone(),
            step: fallback.step.clone(),
            final_witness: self.final_witness.clone(),
            start_fallback: fallback.start_state,
            step_fallback: fallback.step_state,
            final_fallback: fallback.final_state,
        };
        let output = start_output_native(self.public_bind, &self.start);
        trace.push(TraceStep {
            circuit: start_circuit,
            input,
            output,
        });
        input = output;

        for step in &self.step_witnesses {
            let circuit = UniformCircuit {
                final_flag: false,
                start: self.start.clone(),
                step: step.clone(),
                final_witness: self.final_witness.clone(),
                start_fallback: fallback.start_state,
                step_fallback: fallback.step_state,
                final_fallback: fallback.final_state,
            };
            let output = step_output_native(input, step);
            trace.push(TraceStep {
                circuit,
                input,
                output,
            });
            input = output;
        }

        let mut padding_opening = self.final_witness.opening;
        for _ in 0..self.padding_steps {
            let step = StepWitness {
                opening: padding_opening,
                entry: padding_entry(),
            };
            let circuit = UniformCircuit {
                final_flag: false,
                start: self.start.clone(),
                step: step.clone(),
                final_witness: self.final_witness.clone(),
                start_fallback: fallback.start_state,
                step_fallback: fallback.step_state,
                final_fallback: fallback.final_state,
            };
            let output = step_output_native(input, &step);
            trace.push(TraceStep {
                circuit,
                input,
                output,
            });
            input = output;
            // Padding is specified to leave every accumulator opening value
            // unchanged, including its blinding rho.
            padding_opening = step.opening;
        }

        let final_circuit = UniformCircuit {
            final_flag: true,
            start: self.start.clone(),
            step: fallback.step.clone(),
            final_witness: self.final_witness.clone(),
            start_fallback: fallback.start_state,
            step_fallback: fallback.step_state,
            final_fallback: fallback.final_state,
        };
        let output = self.expected_final_state();
        trace.push(TraceStep {
            circuit: final_circuit,
            input,
            output,
        });
        trace
    }

    /// Direct-baseline trace without privacy padding: start, T real entries,
    /// final.  The standalone branch circuits are deliberately different
    /// shapes, which lets the benchmark report their true individual costs.
    pub fn branch_steps_unpadded(&self) -> Vec<TraceStep<BranchCircuit>> {
        let mut trace = Vec::with_capacity(self.entries.len() + 2);
        let fallback = self.fallbacks();
        let mut input = self.start_state;
        let start = BranchCircuit {
            branch: Branch::Start,
            start: self.start.clone(),
            step: fallback.step.clone(),
            final_witness: self.final_witness.clone(),
        };
        let output = start_output_native(self.public_bind, &self.start);
        trace.push(TraceStep {
            circuit: start,
            input,
            output,
        });
        input = output;
        for step_witness in &self.step_witnesses {
            let circuit = BranchCircuit {
                branch: Branch::Step,
                start: self.start.clone(),
                step: step_witness.clone(),
                final_witness: self.final_witness.clone(),
            };
            let output = step_output_native(input, step_witness);
            trace.push(TraceStep {
                circuit,
                input,
                output,
            });
            input = output;
        }
        let final_circuit = BranchCircuit {
            branch: Branch::Final,
            start: self.start.clone(),
            step: fallback.step,
            final_witness: self.final_witness.clone(),
        };
        trace.push(TraceStep {
            circuit: final_circuit,
            input,
            output: self.expected_final_state(),
        });
        trace
    }

    pub(crate) fn reblinded(&self, rho: F) -> Self {
        let mut presentation = self.clone();
        presentation.rho = rho;
        presentation.start.rho = rho;
        presentation.final_witness.opening.rho = rho;
        for step in &mut presentation.step_witnesses {
            step.opening.rho = rho;
        }
        let mut state = start_output_native(presentation.public_bind, &presentation.start);
        for step in &presentation.step_witnesses {
            state = step_output_native(state, step);
        }
        presentation.pre_final_state = state;
        presentation
    }

    fn fallbacks(&self) -> Fallbacks {
        Fallbacks {
            start_state: self.start_state,
            step_state: start_output_native(self.public_bind, &self.start),
            final_state: self.pre_final_state,
            step: self.step_witnesses[0].clone(),
        }
    }
}

#[derive(Clone)]
struct Fallbacks {
    start_state: State,
    step_state: State,
    final_state: State,
    step: StepWitness,
}

#[derive(Clone)]
struct IssuedRecord {
    entries: Vec<EntryWitness>,
    statement: StatementWitness,
    signature: schnorr::Signature,
    nk: F,
    r: F,
}

fn validate_shape(t: usize, n: usize, index: usize) -> Result<(), IssuanceError> {
    if t == 0 {
        return Err(IssuanceError::ZeroSteps);
    }
    if (t as u128) >= (1u128 << 32) {
        return Err(IssuanceError::TooManySteps);
    }
    if n == 0 {
        return Err(IssuanceError::EmptyLog);
    }
    if (n as u128) > MAX_TREE_SIZE as u128 {
        return Err(IssuanceError::LogTooLarge);
    }
    if index >= n {
        return Err(IssuanceError::LeafIndexOutOfRange);
    }
    Ok(())
}

fn issue_record<R: RngCore + CryptoRng>(
    t: usize,
    tool_digest: (F, F),
    allow_path: [F; ALLOWLIST_DEPTH],
    issuer_secret: schnorr::Scalar,
    rng: &mut R,
) -> IssuedRecord {
    let entries = inventory_entries(t, tool_digest, allow_path, rng);
    let task_binding = F::random(&mut *rng);
    let mut transcript = transcript_start_native(task_binding);
    for (position, entry) in entries.iter().enumerate() {
        transcript = transcript_step_native(transcript, F::from((position + 1) as u64), entry);
    }
    let nk = F::random(&mut *rng);
    let r = F::random(&mut *rng);
    let statement = StatementWitness {
        profile_tag: F::from(PROFILE_B_TAG),
        task_binding,
        step_count: F::from(t as u64),
        transcript,
        nk_commitment: nk_commitment_native(nk, r),
    };
    let signature = schnorr::sign(issuer_secret, statement_hash_native(statement), &mut *rng);
    // The native result is intentionally not checked with `verify_native`;
    // final-circuit constraints, not a host boolean, enforce the signature.
    IssuedRecord {
        entries,
        statement,
        signature,
        nk,
        r,
    }
}

fn inventory_entries<R: RngCore + CryptoRng>(
    t: usize,
    tool_digest: (F, F),
    allow_path: [F; ALLOWLIST_DEPTH],
    rng: &mut R,
) -> Vec<EntryWitness> {
    (0..t)
        .map(|position| {
            let kind = match position % 4 {
                0 => KIND_TOOL,
                1 => KIND_EGRESS,
                2 => KIND_FILE,
                _ => KIND_PAYMENT,
            };
            let (d_hi, d_lo) = if kind == KIND_TOOL {
                tool_digest
            } else {
                (random_limb(rng), random_limb(rng))
            };
            EntryWitness {
                kind: F::from(kind),
                d_hi,
                d_lo,
                allow_index: F::ZERO,
                allow_path: if kind == KIND_TOOL {
                    allow_path
                } else {
                    [F::ZERO; ALLOWLIST_DEPTH]
                },
            }
        })
        .collect()
}

fn padding_entry() -> EntryWitness {
    EntryWitness {
        kind: F::from(KIND_PADDING),
        d_hi: F::ZERO,
        d_lo: F::ZERO,
        allow_index: F::ZERO,
        allow_path: [F::ZERO; ALLOWLIST_DEPTH],
    }
}

fn advance_opening(mut opening: AccOpening, entry: &EntryWitness) -> AccOpening {
    if entry.kind != F::from(KIND_PADDING) {
        let next_index = opening.index + F::ONE;
        opening.transcript = transcript_step_native(opening.transcript, next_index, entry);
        opening.index = next_index;
        if entry.kind == F::from(KIND_PAYMENT) {
            opening.pay_count += F::ONE;
        }
    }
    opening
}

fn random_limb<R: RngCore>(rng: &mut R) -> F {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes.into_iter().fold(F::ZERO, |value, byte| {
        value * F::from(256) + F::from(byte as u64)
    })
}

/// Fixed-depth sparse-tree root and membership path. `leaves` contains the
/// occupied prefix; every remaining position is the distinct `H_empty()`.
fn tree_root_and_path(leaves: &[F], index: usize, depth: usize) -> (F, Vec<F>) {
    let leaves: Vec<_> = leaves.iter().copied().map(NativeField).collect();
    let (root, path) = zkar_circuit::tree_root_and_path::<NativeHasher>(&leaves, index, depth);
    (root.0, path.into_iter().map(|value| value.0).collect())
}

fn vec_to_array<const N: usize>(values: Vec<F>) -> [F; N] {
    values
        .try_into()
        .unwrap_or_else(|_| panic!("internal tree path has wrong fixed depth"))
}
