use crate::{
    issuance::Fixture,
    proofs::{self, Compressed, CompressionProverKey, Parameters},
    relation::UniformCircuit,
    F,
};
use ff::Field;
use nova_snark::errors::NovaError;
use rand_core::OsRng;

pub struct PresentationProof {
    proof: Compressed<UniformCircuit>,
    fold_count: usize,
    rho: F,
}

impl PresentationProof {
    pub fn proof(&self) -> &Compressed<UniformCircuit> {
        &self.proof
    }

    pub fn into_proof(self) -> Compressed<UniformCircuit> {
        self.proof
    }

    pub fn fold_count(&self) -> usize {
        self.fold_count
    }

    /// Prover-side accumulator blinding, exposed for presentation audits.
    pub fn rho(&self) -> F {
        self.rho
    }
}

impl Fixture {
    /// Samples new accumulator blinding and produces one complete proof. No
    /// caller-supplied blinding is accepted by the production presentation API.
    pub fn present(
        &self,
        parameters: &Parameters<UniformCircuit>,
        prover_key: &CompressionProverKey<UniformCircuit>,
    ) -> Result<PresentationProof, NovaError> {
        let fixture = self.reblinded(F::random(OsRng));
        let circuits: Vec<_> = fixture
            .uniform_steps()
            .into_iter()
            .map(|step| step.circuit)
            .collect();
        check_fold_count(circuits.len())?;
        let recursive = proofs::fold(parameters, &circuits, &fixture.initial_state())?;
        let proof = Compressed::prove(parameters, prover_key, &recursive)?;
        Ok(PresentationProof {
            proof,
            fold_count: circuits.len(),
            rho: fixture.rho,
        })
    }
}

/// The receipt format carries at most `MAX_FOLD_COUNT` folds, so a run with
/// more than `MAX_FOLD_COUNT - 2` steps has no transportable proof. Refuse it
/// before the folding work starts.
fn check_fold_count(folds: usize) -> Result<(), NovaError> {
    if folds > zkar_core::statement::MAX_FOLD_COUNT as usize {
        return Err(NovaError::ProofVerifyError {
            reason: "fold count is above the receipt format limit of 2^20".to_owned(),
        });
    }
    // The receipt format also needs a power of two, at least 4. A count
    // that is not padded would show the true length of the run.
    if folds < 4 || !folds.is_power_of_two() {
        return Err(NovaError::ProofVerifyError {
            reason: "fold count is not a power of two from 4 through 2^20".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_fold_count;
    use crate::{
        issuance::Fixture,
        proofs::{self, Compressed},
        relation::ACC,
    };

    #[test]
    fn fold_count_limit_matches_the_receipt_format() {
        assert!(check_fold_count(4).is_ok());
        assert!(check_fold_count(1 << 20).is_ok());
        assert!(check_fold_count((1 << 20) + 1).is_err());
        assert!(check_fold_count(0).is_err());
        assert!(check_fold_count(2).is_err());
        assert!(check_fold_count(12).is_err());
        assert!(check_fold_count(16).is_ok());
        assert!(check_fold_count(1 << 21).is_err());
    }

    #[test]
    fn public_uniform_traces_reuse_issuance_blinding() {
        let fixture = Fixture::benchmark_deterministic(1, 4, 2, 0x5341525a4b).unwrap();
        let first = fixture.uniform_steps();
        let second = fixture.uniform_steps();
        assert_eq!(first[0].output, second[0].output);
        for step in first.iter().chain(&second) {
            assert_eq!(step.circuit.start.rho, fixture.rho);
            assert_eq!(step.circuit.step.opening.rho, fixture.rho);
            assert_eq!(step.circuit.final_witness.opening.rho, fixture.rho);
        }
    }

    #[test]
    #[ignore = "real cryptographic proofs; run the release proof integration suite"]
    fn presentations_keep_public_values_and_use_fresh_blinding() {
        let fixture = Fixture::benchmark_deterministic(2, 4, 2, 0x5341525a4b).unwrap();
        let circuit = fixture.uniform_steps()[0].circuit.clone();
        let parameters = proofs::setup(&circuit).unwrap();
        let (prover_key, raw_vk) = Compressed::setup(&parameters).unwrap();
        let digest = proofs::vk_digest(&raw_vk).unwrap();
        let verifier_key = proofs::PinnedVerifierKey::new(raw_vk, &digest).unwrap();

        let first = fixture.present(&parameters, &prover_key).unwrap();
        let second = fixture.present(&parameters, &prover_key).unwrap();
        let public_input = fixture.public_bind.to_array();
        for presentation in [&first, &second] {
            proofs::verify(
                presentation.proof(),
                &verifier_key,
                presentation.fold_count(),
                &public_input,
                fixture.nullifier,
            )
            .unwrap();
        }
        assert_eq!(first.fold_count(), second.fold_count());
        assert_ne!(first.rho(), second.rho());

        let first_trace = fixture.reblinded(first.rho()).uniform_steps();
        let second_trace = fixture.reblinded(second.rho()).uniform_steps();
        assert_ne!(first_trace[0].output[ACC], second_trace[0].output[ACC]);
        for (index, step) in second_trace.iter().enumerate() {
            assert_eq!(step.circuit.start.rho, second.rho(), "start {index}");
            assert_eq!(
                step.circuit.step.opening.rho,
                second.rho(),
                "step opening {index}"
            );
            assert_eq!(
                step.circuit.final_witness.opening.rho,
                second.rho(),
                "final opening {index}"
            );
        }
    }
}
