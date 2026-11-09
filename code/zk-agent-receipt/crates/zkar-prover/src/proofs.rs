//! Proof-system integration. Only compressed proofs are presentation artifacts.
use crate::{E1, E2, F, S1, S2};
use ff::{Field, PrimeField};
use nova_snark::{
    errors::NovaError,
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait},
};

pub type Parameters<C> = PublicParams<E1, E2, C>;
pub type Recursive<C> = RecursiveSNARK<E1, E2, C>;
pub type Compressed<C> = CompressedSNARK<E1, E2, C, S1, S2>;
pub type CompressionProverKey<C> = nova_snark::nova::ProverKey<E1, E2, C, S1, S2>;
pub type CompressionVerifierKey<C> = nova_snark::nova::VerifierKey<E1, E2, C, S1, S2>;
pub type Direct<C> = nova_snark::spartan::direct::DirectSNARK<E1, S1, C>;

pub fn setup<C: StepCircuit<F>>(circuit: &C) -> Result<Parameters<C>, NovaError> {
    Parameters::setup(circuit, &*S1::ck_floor(), &*S2::ck_floor())
}

/// Includes the first step computed by `new`; Nova's first `prove_step` counts
/// that step without computing it again. Do not omit that first call.
pub fn fold<C: StepCircuit<F>>(
    pp: &Parameters<C>,
    circuits: &[C],
    initial: &[F],
) -> Result<Recursive<C>, NovaError> {
    let first = circuits
        .first()
        .ok_or_else(|| invalid("empty computation"))?;
    let mut proof = Recursive::new(pp, first, initial)?;
    for (i, circuit) in circuits.iter().enumerate() {
        proof.prove_step(pp, circuit)?;
        if (i + 1) % 64 == 0 {
            eprintln!("recursive folds: {}/{}", i + 1, circuits.len());
        }
    }
    Ok(proof)
}

fn invalid(reason: &str) -> NovaError {
    NovaError::ProofVerifyError {
        reason: reason.to_owned(),
    }
}

const VK_DIGEST_LABEL: &[u8] = b"SAR-ZK-vk-digest-v0.4\0";

/// SHA-256 over a domain label and the bincode encoding of a verification key.
/// Publish this digest with a release; verifiers pin it.
pub fn vk_digest<C: StepCircuit<F>>(
    vk: &CompressionVerifierKey<C>,
) -> Result<[u8; 32], bincode::error::EncodeError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(VK_DIGEST_LABEL);
    hasher.update(encode(vk)?);
    Ok(hasher.finalize().into())
}

/// A verification key checked once, at load time, against a digest the
/// verifier pinned in advance. A key that came with a proof could belong to
/// any circuit, so `verify` accepts only this type.
pub struct PinnedVerifierKey<C: StepCircuit<F>> {
    vk: CompressionVerifierKey<C>,
    digest: [u8; 32],
}

impl<C: StepCircuit<F>> PinnedVerifierKey<C> {
    pub fn new(vk: CompressionVerifierKey<C>, pinned_digest: &[u8; 32]) -> Result<Self, NovaError> {
        let digest = vk_digest(&vk).map_err(|_| invalid("cannot encode verification key"))?;
        if &digest != pinned_digest {
            return Err(invalid("verification key does not match the pinned digest"));
        }
        Ok(Self {
            vk,
            digest: *pinned_digest,
        })
    }

    pub fn key(&self) -> &CompressionVerifierKey<C> {
        &self.vk
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Verify against verifier-owned public values, including the final nullifier.
/// The caller must separately authenticate the signed log head and pin the
/// issuer, policy, and scope. The state convention is fixed by SAR-ZK §9.1.
pub fn verify<C: StepCircuit<F>>(
    proof: &Compressed<C>,
    vk: &PinnedVerifierKey<C>,
    folds: usize,
    public_bind: &[F; 6],
    nullifier: F,
) -> Result<(), NovaError> {
    if !(4..=zkar_core::statement::MAX_FOLD_COUNT as usize).contains(&folds)
        || !folds.is_power_of_two()
    {
        return Err(invalid(
            "fold count must be a power-of-two padding bucket from four through 2^20",
        ));
    }
    if public_bind[0] != F::from(11) {
        return Err(invalid("this prover supports only profile b"));
    }
    let mut initial = vec![F::ZERO; 9];
    initial[2..8].copy_from_slice(public_bind);
    let mut expected = initial.clone();
    expected[0] = F::from(2);
    expected[8] = nullifier;
    let actual = proof.verify(&vk.vk, folds, &initial)?;
    if actual != expected {
        return Err(invalid("final state must be HALT, zero accumulator, unchanged public binding, expected nullifier"));
    }
    Ok(())
}

/// Verifier-owned context. These values must come from pinned keys and the
/// verifier's chosen policy/scope, not merely be copied from an untrusted proof.
pub struct VerifierContext<'a> {
    pub public_bind: [F; 6],
    pub nullifier: F,
    pub log_id: &'a str,
    pub log_public_key: &'a [u8; 32],
}

impl VerifierContext<'_> {
    /// Exact §7.1 bytes binding the signed log root and size to this proof's
    /// expected state. This also lets an independent log signer sign fixtures.
    pub fn log_head_bytes(&self) -> Result<Vec<u8>, zkar_core::ZkarError> {
        if !zkar_core::lexical::is_id(self.log_id) {
            return Err(zkar_core::ZkarError::Other("invalid pinned log identifier"));
        }
        let decimal = |value: F| {
            num_bigint::BigUint::from_bytes_le(value.to_repr().as_ref()).to_str_radix(10)
        };
        let public = zkar_core::statement::PublicInput {
            profile: zkar_core::PROFILE_B.to_owned(),
            issuer_key_commitment: decimal(self.public_bind[1]),
            log_root: decimal(self.public_bind[2]),
            tree_size: decimal(self.public_bind[3]),
            log_id: self.log_id.to_owned(),
            log_head_signature: String::new(),
            policy_commitment: decimal(self.public_bind[4]),
            nullifier_scope: decimal(self.public_bind[5]),
            nullifier: decimal(self.nullifier),
        };
        zkar_core::verify::canonical_head_bytes(&public)
    }
}

/// Verify both the pinned Ed25519 log head and the compressed receipt proof.
/// Replay-set storage is the relying party's responsibility (§9.3 step 5).
pub fn verify_authenticated<C: StepCircuit<F>>(
    proof: &Compressed<C>,
    vk: &PinnedVerifierKey<C>,
    folds: usize,
    context: &VerifierContext<'_>,
    log_signature: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    zkar_core::verify::verify_log_head_signature(
        context.log_public_key,
        &context.log_head_bytes()?,
        log_signature,
    )?;
    verify(proof, vk, folds, &context.public_bind, context.nullifier)?;
    Ok(())
}

/// A single direct circuit containing a sequence of branch circuits. Branch
/// choices are part of its shape/key, not unconstrained witness dispatch.
#[derive(Clone)]
pub struct Sequence<C> {
    pub circuits: Vec<C>,
}

impl<C: StepCircuit<F>> StepCircuit<F> for Sequence<C> {
    fn arity(&self) -> usize {
        9
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let mut state = z.to_vec();
        for (i, circuit) in self.circuits.iter().enumerate() {
            state = circuit.synthesize(&mut cs.namespace(|| format!("branch_{i}")), &state)?;
        }
        Ok(state)
    }
}

/// Same bincode-2 legacy configuration as Nova's examples, without zlib.
pub fn encode<T: serde::Serialize>(proof: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(proof, bincode::config::legacy())
}

/// Raw application constraints, excluding Nova's recursive verifier and the
/// direct wrapper's input/output allocations.
pub fn constraint_count<C: StepCircuit<F>>(circuit: &C) -> Result<usize, SynthesisError> {
    let mut cs = nova_snark::frontend::shape_cs::ShapeCS::<E1>::new();
    let input = (0..circuit.arity())
        .map(|i| AllocatedNum::alloc(cs.namespace(|| format!("state_{i}")), || Ok(F::ZERO)))
        .collect::<Result<Vec<_>, _>>()?;
    circuit.synthesize(&mut cs, &input)?;
    Ok(cs.num_constraints())
}
