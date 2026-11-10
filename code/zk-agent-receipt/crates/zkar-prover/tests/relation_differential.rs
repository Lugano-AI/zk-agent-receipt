//! Native agreement tests for the profile-b relations.
//!
//! Each case starts with the plain relation generator. The adapter only
//! changes field and witness transport for the circuit relation.

use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem},
    traits::circuit::StepCircuit,
};
use relation as baseline_relation;
use zkar_prover::{
    poseidon,
    relation::{
        issuer_key_commitment_native, log_leaf_native, start_output_native, statement_hash_native,
        step_output_native, transcript_start_native, transcript_step_native, AccOpening,
        EntryWitness, FinalWitness, PolicyOpening, PublicBind, StartWitness, State,
        StatementWitness, StepWitness, TraceStep, UniformCircuit, ALLOWLIST_DEPTH, KIND_PAYMENT,
        KIND_TOOL, LOG_DEPTH,
    },
    schnorr::{self, PallasPoint, Scalar, Signature},
    F,
};

#[derive(Clone)]
struct SharedRecord {
    input: baseline_relation::Input,
    start_task_binding: F,
}

struct CircuitRecord {
    bind: PublicBind,
    start: StartWitness,
    steps: Vec<StepWitness>,
    final_witness: FinalWitness,
    expected_nullifier: F,
}

fn generated_record(t: usize, marker: u8) -> SharedRecord {
    let mut seed = baseline_relation::DEFAULT_FIXTURE_SEED;
    seed[0] ^= marker;
    let input = baseline_relation::generate(t, seed).expect("plain fixture generation");
    let start_task_binding = field_from_wire(input.statement.task_binding);
    SharedRecord {
        input,
        start_task_binding,
    }
}

fn field_from_wire(wire: baseline_relation::FieldWire) -> F {
    let mut repr = <F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&wire);
    Option::<F>::from(F::from_repr(repr)).expect("generated field wire is canonical")
}

fn field_wire(value: F) -> baseline_relation::FieldWire {
    let repr = value.to_repr();
    let mut wire = [0u8; 32];
    wire.copy_from_slice(repr.as_ref());
    wire
}

fn scalar_from_wire(wire: baseline_relation::FieldWire) -> Scalar {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&wire);
    Option::<Scalar>::from(Scalar::from_repr(repr)).expect("generated scalar wire is canonical")
}

fn scalar_wire(value: Scalar) -> baseline_relation::FieldWire {
    let repr = value.to_repr();
    let mut wire = [0u8; 32];
    wire.copy_from_slice(repr.as_ref());
    wire
}

fn limb_from_wire(wire: [u8; 16]) -> F {
    wire.into_iter().fold(F::ZERO, |value, byte| {
        value * F::from(256) + F::from(byte as u64)
    })
}

fn point_from_wire(point: &baseline_relation::PointWire) -> PallasPoint {
    PallasPoint {
        x: field_from_wire(point.x),
        y: field_from_wire(point.y),
        is_identity: false,
    }
}

fn point_wire(point: PallasPoint) -> baseline_relation::PointWire {
    assert!(!point.is_identity, "test signer must not be the identity");
    baseline_relation::PointWire {
        x: field_wire(point.x),
        y: field_wire(point.y),
    }
}

fn statement_from_input(input: &baseline_relation::Input) -> StatementWitness {
    StatementWitness {
        profile_tag: field_from_wire(input.statement.profile_tag),
        task_binding: field_from_wire(input.statement.task_binding),
        step_count: field_from_wire(input.statement.step_count),
        transcript: field_from_wire(input.statement.transcript),
        nk_commitment: field_from_wire(input.statement.nk_commitment),
    }
}

fn signature_from_input(input: &baseline_relation::Input) -> Signature {
    Signature {
        r: point_from_wire(&input.signature.r),
        s: scalar_from_wire(input.signature.s),
    }
}

fn signature_wire(signature: Signature) -> baseline_relation::SchnorrSignature {
    baseline_relation::SchnorrSignature {
        r: point_wire(signature.r),
        s: scalar_wire(signature.s),
    }
}

fn circuit_record(record: &SharedRecord) -> CircuitRecord {
    let input = &record.input;
    let policy = PolicyOpening {
        allowlist_root: field_from_wire(input.policy.allowlist_root),
        egress_allowed: F::from(input.policy.egress_allowed as u64),
        payment_bound: F::from(input.policy.payment_bound as u64),
    };
    let bind = PublicBind {
        profile_tag: field_from_wire(input.profile_tag),
        issuer_key_commitment: field_from_wire(input.issuer_key_commitment),
        log_root: field_from_wire(input.log_root),
        tree_size: F::from(input.tree_size as u64),
        policy_commitment: field_from_wire(input.policy.commitment),
        nullifier_scope: field_from_wire(input.nullifier_scope),
    };
    let entries = input
        .entries
        .iter()
        .enumerate()
        .map(|(entry_index, entry)| {
            let path = if entry.kind == KIND_TOOL as u8 {
                input
                    .tool_paths
                    .iter()
                    .find(|path| path.entry_index == entry_index as u32)
                    .expect("generated tool path")
            } else {
                // Non-tool paths are not part of the plain relation input.
                // Zero is the circuit's neutral witness for those slots.
                return EntryWitness {
                    kind: F::from(entry.kind as u64),
                    d_hi: limb_from_wire(entry.digest_hi),
                    d_lo: limb_from_wire(entry.digest_lo),
                    allow_index: F::ZERO,
                    allow_path: [F::ZERO; ALLOWLIST_DEPTH],
                };
            };
            EntryWitness {
                kind: F::from(entry.kind as u64),
                d_hi: limb_from_wire(entry.digest_hi),
                d_lo: limb_from_wire(entry.digest_lo),
                allow_index: F::from(path.leaf_index as u64),
                allow_path: path.siblings.map(field_from_wire),
            }
        })
        .collect::<Vec<_>>();

    let start = StartWitness {
        task_binding: record.start_task_binding,
        policy,
        rho: F::from(29),
    };
    let mut opening = AccOpening {
        transcript: transcript_start_native(start.task_binding),
        index: F::ZERO,
        pay_count: F::ZERO,
        policy,
        rho: start.rho,
    };
    let mut steps = Vec::with_capacity(entries.len());
    for entry in entries {
        let step = StepWitness {
            opening,
            entry,
        };
        opening = advance_opening(step.opening, &step.entry);
        steps.push(step);
    }

    CircuitRecord {
        bind,
        start,
        steps,
        final_witness: FinalWitness {
            opening,
            statement: statement_from_input(input),
            issuer_pk: point_from_wire(&input.issuer_public_key),
            signature: signature_from_input(input),
            log_path: input.log_path.map(field_from_wire),
            leaf_index: F::from(input.leaf_index as u64),
            nk: field_from_wire(input.nk),
            r: field_from_wire(input.r),
        },
        expected_nullifier: field_from_wire(input.expected_nullifier),
    }
}

fn advance_opening(mut opening: AccOpening, entry: &EntryWitness) -> AccOpening {
    let next_index = opening.index + F::ONE;
    opening.transcript = transcript_step_native(opening.transcript, next_index, entry);
    opening.index = next_index;
    if entry.kind == F::from(KIND_PAYMENT) {
        opening.pay_count += F::ONE;
    }
    opening
}

fn uniform_trace(record: &SharedRecord) -> Vec<TraceStep<UniformCircuit>> {
    let record = circuit_record(record);
    let first_step = record
        .steps
        .first()
        .expect("generated record has one step")
        .clone();
    let initial = record.bind.initial_state();
    let start_output = start_output_native(record.bind, &record.start);
    let mut input = start_output;
    let mut outputs = Vec::with_capacity(record.steps.len());
    for step in &record.steps {
        input = step_output_native(input, step);
        outputs.push(input);
    }
    let final_fallback = input;
    let mut trace = Vec::with_capacity(record.steps.len() + 2);
    trace.push(TraceStep {
        circuit: UniformCircuit {
            final_flag: false,
            start: record.start.clone(),
            step: first_step.clone(),
            final_witness: record.final_witness.clone(),
            start_fallback: initial,
            step_fallback: start_output,
            final_fallback,
        },
        input: initial,
        output: start_output,
    });
    let mut previous = start_output;
    for (step, output) in record.steps.iter().zip(outputs) {
        trace.push(TraceStep {
            circuit: UniformCircuit {
                final_flag: false,
                start: record.start.clone(),
                step: step.clone(),
                final_witness: record.final_witness.clone(),
                start_fallback: initial,
                step_fallback: start_output,
                final_fallback,
            },
            input: previous,
            output,
        });
        previous = output;
    }
    trace.push(TraceStep {
        circuit: UniformCircuit {
            final_flag: true,
            start: record.start,
            step: first_step,
            final_witness: record.final_witness,
            start_fallback: initial,
            step_fallback: start_output,
            final_fallback,
        },
        input: previous,
        output: record.bind.final_state(record.expected_nullifier),
    });
    trace
}

fn circuit_step_accepts(circuit: &UniformCircuit, input: State, expected: State) -> bool {
    let mut cs = TestConstraintSystem::<F>::new();
    let state = input
        .iter()
        .enumerate()
        .map(|(index, value)| {
            AllocatedNum::alloc(cs.namespace(|| format!("state_{index}")), || Ok(*value))
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("test state allocation");
    let Ok(output) = circuit.synthesize(&mut cs, &state) else {
        return false;
    };
    for (index, value) in expected.iter().enumerate() {
        let variable = output[index].get_variable();
        cs.enforce(
            || format!("expected output {index}"),
            |lc| lc + variable + (-*value, TestConstraintSystem::<F>::one()),
            |lc| lc + TestConstraintSystem::<F>::one(),
            |lc| lc,
        );
    }
    cs.is_satisfied()
}

fn circuit_accepts(record: &SharedRecord) -> bool {
    uniform_trace(record)
        .into_iter()
        .all(|step| circuit_step_accepts(&step.circuit, step.input, step.output))
}

fn plain_accepts(record: &SharedRecord) -> bool {
    baseline_relation::verify(&record.input).is_ok()
}

fn assert_agrees(label: &str, record: &SharedRecord, expected: bool) {
    let plain = plain_accepts(record);
    let circuit = circuit_accepts(record);
    assert_eq!(plain, expected, "plain result for {label}");
    assert_eq!(circuit, expected, "circuit result for {label}");
    assert_eq!(circuit, plain, "relation mismatch for {label}");
}

fn u64_wire(value: u64) -> baseline_relation::FieldWire {
    let mut wire = [0u8; 32];
    wire[..8].copy_from_slice(&value.to_le_bytes());
    wire
}

fn recompute_policy_commitment(input: &mut baseline_relation::Input) {
    input.policy.commitment = baseline_relation::hash(
        "SAR-ZK policy",
        &[
            input.policy.allowlist_root,
            u64_wire(input.policy.egress_allowed as u64),
            u64_wire(input.policy.payment_bound as u64),
        ],
    )
    .expect("valid policy fields");
}

fn replace_log_with_single_statement_leaf(input: &mut baseline_relation::Input) {
    let statement_hash = statement_hash_native(statement_from_input(input));
    let mut root = log_leaf_native(statement_hash);
    let mut empty = poseidon::hash_native("SAR-ZK empty", &[]);
    let mut path = [F::ZERO; LOG_DEPTH];
    for sibling in &mut path {
        *sibling = empty;
        root = poseidon::hash_native("SAR-ZK node", &[root, empty]);
        empty = poseidon::hash_native("SAR-ZK node", &[empty, empty]);
    }
    input.log_path = path.map(field_wire);
    input.log_root = field_wire(root);
    input.tree_size = 1;
    input.leaf_index = 0;
}

fn signed_separate_start_binding_record() -> SharedRecord {
    let mut record = generated_record(4, 0x91);
    let signed_binding = record.start_task_binding + F::ONE;
    assert_ne!(signed_binding, record.start_task_binding);
    record.input.statement.task_binding = field_wire(signed_binding);

    let signer = Scalar::from(7);
    let issuer = schnorr::public_key(signer);
    record.input.issuer_public_key = point_wire(issuer);
    record.input.issuer_key_commitment = field_wire(issuer_key_commitment_native(issuer));
    let statement_hash = statement_hash_native(statement_from_input(&record.input));
    record.input.signature = signature_wire(schnorr::sign_with_nonce(
        signer,
        Scalar::from(11),
        statement_hash,
    ));
    replace_log_with_single_statement_leaf(&mut record.input);
    record
}

#[test]
fn shared_generated_records_agree_for_honest_step_counts_and_kinds() {
    let mut seen_kinds = [false; 5];
    for (marker, t) in [(1u8, 1usize), (2, 2), (3, 3), (4, 4), (5, 5), (6, 8)] {
        let record = generated_record(t, marker);
        for entry in &record.input.entries {
            seen_kinds[entry.kind as usize] = true;
        }
        assert_agrees(&format!("honest t={t}"), &record, true);
    }
    for (kind, present) in seen_kinds.iter().enumerate().skip(1) {
        assert!(*present, "fixture suite missed entry kind {kind}");
    }
}

#[test]
fn changed_shared_records_agree() {
    let source = generated_record(4, 0x52);

    let mut wrong_signature = source.clone();
    wrong_signature.input.signature.s = scalar_wire(
        scalar_from_wire(wrong_signature.input.signature.s) + Scalar::ONE,
    );
    assert_agrees("wrong signature", &wrong_signature, false);

    let mut wrong_log_path = source.clone();
    wrong_log_path.input.log_path[0] =
        field_wire(field_from_wire(wrong_log_path.input.log_path[0]) + F::ONE);
    assert_agrees("wrong log path", &wrong_log_path, false);

    let mut wrong_policy_opening = source.clone();
    wrong_policy_opening.input.policy.payment_bound += 1;
    assert_agrees("wrong policy opening", &wrong_policy_opening, false);

    let mut payment_over_bound = source.clone();
    let payment_count = payment_over_bound
        .input
        .entries
        .iter()
        .filter(|entry| entry.kind == KIND_PAYMENT as u8)
        .count() as u32;
    assert!(payment_count > 0, "fixture must contain a payment");
    payment_over_bound.input.policy.payment_bound = payment_count - 1;
    recompute_policy_commitment(&mut payment_over_bound.input);
    assert_agrees("payment over bound", &payment_over_bound, false);

    let mut tool_outside_allowlist = source.clone();
    let tool_index = tool_outside_allowlist
        .input
        .entries
        .iter()
        .position(|entry| entry.kind == KIND_TOOL as u8)
        .expect("fixture must contain a tool");
    tool_outside_allowlist.input.entries[tool_index].digest_hi[0] ^= 1;
    assert_agrees("tool outside allowlist", &tool_outside_allowlist, false);

    let mut wrong_step_count = source.clone();
    wrong_step_count.input.statement.step_count = u64_wire(source.input.entries.len() as u64 + 1);
    assert_agrees("wrong step count", &wrong_step_count, false);

    let mut wrong_nullifier = source.clone();
    wrong_nullifier.input.expected_nullifier =
        field_wire(field_from_wire(wrong_nullifier.input.expected_nullifier) + F::ONE);
    assert_agrees("wrong nullifier", &wrong_nullifier, false);

    let mut wrong_transcript = source;
    wrong_transcript.input.statement.transcript =
        field_wire(field_from_wire(wrong_transcript.input.statement.transcript) + F::ONE);
    assert_agrees("wrong transcript", &wrong_transcript, false);
}

#[test]
fn nova_accepts_and_zkvm_rejects_a_signed_separate_start_binding() {
    // Nova starts the transcript from the separate start witness. It accepts
    // this record because that witness chains to the signed transcript. The
    // zkVM relation starts from the signed task binding and rejects it.
    let record = signed_separate_start_binding_record();
    assert_ne!(
        record.start_task_binding,
        field_from_wire(record.input.statement.task_binding),
        "the two task bindings must differ"
    );
    assert_eq!(
        baseline_relation::verify(&record.input),
        Err(baseline_relation::Error::TranscriptMismatch),
        "the plain relation must recompute the signed binding"
    );
    assert!(
        circuit_accepts(&record),
        "the circuit relation must keep its stated start-binding behavior"
    );
}
