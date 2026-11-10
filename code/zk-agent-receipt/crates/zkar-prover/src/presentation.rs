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
}
