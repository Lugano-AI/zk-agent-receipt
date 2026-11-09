//! Profile-b Sealed Receipt relation and transparent Nova/Spartan proofs.
pub mod benchmark;
pub mod issuance;
pub mod poseidon;
pub mod presentation;
pub mod proofs;
pub mod relation;
pub mod replay;
pub mod schnorr;
pub mod sealed;
pub type E1 = nova_snark::provider::VestaEngine;
pub type E2 = nova_snark::provider::PallasEngine;
pub type F = <E1 as nova_snark::traits::Engine>::Scalar;
pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<
    E1,
    nova_snark::provider::ipa_pc::EvaluationEngine<E1>,
>;
pub type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<
    E2,
    nova_snark::provider::ipa_pc::EvaluationEngine<E2>,
>;
