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
        let recursive = proofs::fold(parameters, &circuits, &fixture.initial_state())?;
        let proof = Compressed::prove(parameters, prover_key, &recursive)?;
        Ok(PresentationProof {
            proof,
            fold_count: circuits.len(),
            rho: fixture.rho,
        })
    }
}
