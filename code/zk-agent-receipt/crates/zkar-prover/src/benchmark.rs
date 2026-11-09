//! Measurements returned to the fresh-process benchmark driver.
use crate::{
    issuance::Fixture,
    proofs::{self, Compressed, Direct, Sequence},
    relation::BranchCircuit,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, time::Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub setup_seconds: f64,
    pub recursive_seconds: Option<f64>,
    pub compression_seconds: Option<f64>,
    pub prover_seconds: f64,
    pub verifier_seconds: f64,
    pub proof_bytes: usize,
    pub proof_count: usize,
    pub per_proof_bytes: Vec<usize>,
    pub per_proof_setup_seconds: Vec<f64>,
    pub per_proof_prover_seconds: Vec<f64>,
    pub per_proof_verifier_seconds: Vec<f64>,
    pub primary_constraints: usize,
    pub uniform_constraints: usize,
    pub secondary_constraints: usize,
    pub monolithic_constraints: Option<usize>,
    pub branch_constraints: [usize; 3],
    pub folds: usize,
    pub log_leaves: usize,
    pub candidate_set_size: usize,
}

/// One measurement; callers must launch a fresh process for every invocation.
/// The deterministic seed is used only for test/benchmark issuance. Nova uses
/// its own OsRng for proof randomness.
pub fn measure(t: usize, system: &str, seed: u64) -> Result<Measurement, Box<dyn Error>> {
    let fixture = Fixture::benchmark_deterministic(t, 16, 7, seed)?;
    let uniform = fixture.uniform_steps();
    let branches = fixture.branch_steps_unpadded();
    let branch_constraints = [
        proofs::constraint_count(&branches[0].circuit)?,
        proofs::constraint_count(&branches[1].circuit)?,
        proofs::constraint_count(&branches.last().ok_or("missing final branch")?.circuit)?,
    ];
    let mut result = Measurement {
        setup_seconds: 0.0,
        recursive_seconds: None,
        compression_seconds: None,
        prover_seconds: 0.0,
        verifier_seconds: 0.0,
        proof_bytes: 0,
        proof_count: 0,
        per_proof_bytes: vec![],
        per_proof_setup_seconds: vec![],
        per_proof_prover_seconds: vec![],
        per_proof_verifier_seconds: vec![],
        primary_constraints: branch_constraints[1],
        uniform_constraints: proofs::constraint_count(&uniform[0].circuit)?,
        secondary_constraints: 0,
        monolithic_constraints: None,
        branch_constraints,
        folds: uniform.len(),
        log_leaves: fixture.log_leaves,
        candidate_set_size: fixture.candidate_set_size,
    };
    match system {
        "folded" => {
            eprintln!("folded T={t}: setup");
            let circuits: Vec<_> = uniform.into_iter().map(|step| step.circuit).collect();
            let start = Instant::now();
            let pp = proofs::setup(&circuits[0])?;
            let (pk, vk) = Compressed::setup(&pp)?;
            // Pinning happens once at key load, outside the verifier timer.
            let digest = proofs::vk_digest(&vk)?;
            let vk = proofs::PinnedVerifierKey::new(vk, &digest)?;
            result.setup_seconds = start.elapsed().as_secs_f64();
            (result.primary_constraints, result.secondary_constraints) = pp.num_constraints();
            eprintln!("folded T={t}: {} recursive folds", circuits.len());
            let start = Instant::now();
            let recursive = proofs::fold(&pp, &circuits, &fixture.initial_state())?;
            let recursion = start.elapsed().as_secs_f64();
            eprintln!("folded T={t}: compression (recursion {recursion:.3}s)");
            let start = Instant::now();
            let proof = Compressed::prove(&pp, &pk, &recursive)?;
            let compression = start.elapsed().as_secs_f64();
            result.recursive_seconds = Some(recursion);
            result.compression_seconds = Some(compression);
            result.prover_seconds = recursion + compression;
            let bytes = proofs::encode(&proof)?;
            let start = Instant::now();
            proofs::verify(
                &proof,
                &vk,
                circuits.len(),
                &fixture.public_bind.to_array(),
                fixture.nullifier,
            )?;
            result.verifier_seconds = start.elapsed().as_secs_f64();
            result.proof_bytes = bytes.len();
            result.proof_count = 1;
            result.per_proof_bytes.push(bytes.len());
            result.per_proof_setup_seconds.push(result.setup_seconds);
            result.per_proof_prover_seconds.push(result.prover_seconds);
            result
                .per_proof_verifier_seconds
                .push(result.verifier_seconds);
        }
        "monolithic" => {
            let circuit = Sequence {
                circuits: branches.into_iter().map(|s| s.circuit).collect(),
            };
            result.monolithic_constraints = Some(proofs::constraint_count(&circuit)?);
            eprintln!("monolithic T={t}: setup");
            let start = Instant::now();
            let (pk, vk) = Direct::setup(circuit.clone())?;
            result.setup_seconds = start.elapsed().as_secs_f64();
            eprintln!("monolithic T={t}: prove");
            let start = Instant::now();
            let proof = Direct::prove(&pk, circuit, &fixture.initial_state())?;
            result.prover_seconds = start.elapsed().as_secs_f64();
            let bytes = proofs::encode(&proof)?;
            let io: Vec<_> = fixture
                .initial_state()
                .into_iter()
                .chain(fixture.expected_final_state())
                .collect();
            let start = Instant::now();
            proof.verify(&vk, &io)?;
            result.verifier_seconds = start.elapsed().as_secs_f64();
            result.proof_bytes = bytes.len();
            result.proof_count = 1;
            result.per_proof_bytes.push(bytes.len());
            result.per_proof_setup_seconds.push(result.setup_seconds);
            result.per_proof_prover_seconds.push(result.prover_seconds);
            result
                .per_proof_verifier_seconds
                .push(result.verifier_seconds);
        }
        "per-entry" => {
            type C = Sequence<BranchCircuit>;
            let first = C {
                circuits: vec![branches[0].circuit.clone(), branches[1].circuit.clone()],
            };
            let step = C {
                circuits: vec![branches[1].circuit.clone()],
            };
            let final_circuit = C {
                circuits: vec![branches
                    .last()
                    .ok_or("missing final branch")?
                    .circuit
                    .clone()],
            };
            eprintln!("per-entry T={t}: setup (distinct shapes only)");
            let start = Instant::now();
            let first_keys = Direct::setup(first.clone())?;
            let first_setup = start.elapsed().as_secs_f64();
            let start = Instant::now();
            let step_keys = if t > 1 {
                Some(Direct::setup(step)?)
            } else {
                None
            };
            let step_setup = if t > 1 {
                start.elapsed().as_secs_f64()
            } else {
                0.0
            };
            let start = Instant::now();
            let final_keys = Direct::setup(final_circuit.clone())?;
            let final_setup = start.elapsed().as_secs_f64();
            result.setup_seconds = first_setup + step_setup + final_setup;
            for i in 0..=t {
                let (circuit, input, output, keys, setup) = if i == 0 {
                    (
                        first.clone(),
                        branches[0].input,
                        branches[1].output,
                        &first_keys,
                        first_setup,
                    )
                } else if i == t {
                    let last = branches.last().ok_or("missing final branch")?;
                    (
                        final_circuit.clone(),
                        last.input,
                        last.output,
                        &final_keys,
                        final_setup,
                    )
                } else {
                    let trace = &branches[i + 1];
                    (
                        C {
                            circuits: vec![trace.circuit.clone()],
                        },
                        trace.input,
                        trace.output,
                        step_keys.as_ref().ok_or("missing step keys")?,
                        if i == 1 { step_setup } else { 0.0 },
                    )
                };
                if i % 100 == 0 || i == t {
                    eprintln!("per-entry T={t}: proof {}/{}", i + 1, t + 1);
                }
                let start = Instant::now();
                let proof = Direct::prove(&keys.0, circuit, &input)?;
                let proving = start.elapsed().as_secs_f64();
                let bytes = proofs::encode(&proof)?;
                let io: Vec<_> = input.into_iter().chain(output).collect();
                let start = Instant::now();
                proof.verify(&keys.1, &io)?;
                let verification = start.elapsed().as_secs_f64();
                result.prover_seconds += proving;
                result.verifier_seconds += verification;
                result.proof_bytes += bytes.len();
                result.per_proof_bytes.push(bytes.len());
                result.per_proof_setup_seconds.push(setup);
                result.per_proof_prover_seconds.push(proving);
                result.per_proof_verifier_seconds.push(verification);
            }
            result.proof_count = t + 1;
        }
        _ => return Err(format!("unknown benchmark system: {system}").into()),
    }
    Ok(result)
}
