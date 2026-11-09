//! A guest-compatible native mirror of the SAR-ZK v0.4b relation.
//!
//! This crate implements the concrete Profile B statement: canonical Pallas
//! field encodings, the specified P128Pow5T3 sponge, policy and log paths,
//! scoped nullifiers, and Pallas Schnorr verification. It deliberately does
//! not implement the IVC accumulator or the outer Ed25519 log-head check.

#![no_std]

extern crate alloc;

#[cfg(all(feature = "risc0-accelerated", feature = "risc0-legacy-mul"))]
compile_error!("select exactly one RISC0 Poseidon multiplication backend");

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cmp;

#[cfg(any(
    test,
    not(all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    ))
))]
use halo2_poseidon::{Mds, P128Pow5T3, Spec as PoseidonSpec};
use pasta_curves::{
    arithmetic::CurveAffine as PastaCurveAffine,
    group::{
        ff::{Field, PrimeField},
        Curve, CurveAffine as GroupCurveAffine,
    },
    pallas,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

// The guest consumes these fixed canonical limbs directly. Native tests retain
// the upstream implementation as an independent oracle for the generated
// table.
#[cfg(any(
    test,
    all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    )
))]
mod poseidon_constants;

/// A canonical, little-endian encoding of a Pallas base-field element.
pub type FieldWire = [u8; 32];
/// One big-endian 128-bit half of a SHA-256 inventory digest.
pub type DigestLimb = [u8; 16];

/// The only profile implemented by this relation crate.
pub const PROFILE_B_TAG: u64 = 0x0b;
/// Fixed SAR-ZK log-tree depth (spec section 7.2).
pub const LOG_DEPTH: usize = 32;
/// Fixed SAR-ZK allowlist-tree depth (spec section 6).
pub const ALLOWLIST_DEPTH: usize = 16;
/// Largest legal signed log tree size (spec section 7.1).
pub const MAX_TREE_SIZE: u32 = 2_147_483_647;

const KIND_TOOL: u8 = 1;
const KIND_EGRESS: u8 = 2;
const KIND_FILE: u8 = 3;
const KIND_PAYMENT: u8 = 4;

const D_STATEMENT: &str = "SAR-ZK statement";
const D_LEAF: &str = "SAR-ZK leaf";
const D_NODE: &str = "SAR-ZK node";
const D_EMPTY: &str = "SAR-ZK empty";
const D_TRANSCRIPT: &str = "SAR-ZK transcript";
const D_STEP: &str = "SAR-ZK step";
const D_ALLOW: &str = "SAR-ZK allow";
const D_POLICY: &str = "SAR-ZK policy";
const D_NK: &str = "SAR-ZK nk";
const D_NULLIFIER: &str = "SAR-ZK nullifier";
const D_ISSUER: &str = "SAR-ZK issuer";
const D_SCHNORR: &str = "SAR-ZK schnorr";

const DOMAIN_COUNT: usize = 12;
const MAX_CACHED_ARITY: usize = 7;
const MAX_CACHED_NODES: usize = 128;
// Tool witnesses arrive from the untrusted input, so cache only a fixed
// number of them. Entries beyond this limit are still checked normally.
const MAX_CACHED_TOOL_PATHS: usize = 128;

type Fp = pallas::Base;
type Fq = pallas::Scalar;

// Keep the bigint2 Pallas implementation independent from the portable
// fixture/signing path. It is compiled for native unit tests so its point
// parser can be checked against Pasta, and for the selected zkVM backend.
#[cfg(any(
    test,
    all(target_os = "zkvm", feature = "risc0-accelerated")
))]
mod pallas_accelerated;

/// One inventory entry. `kind` is deliberately a byte rather than an enum so
/// malformed serialized inputs can be rejected by [`verify`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// 1 = tool, 2 = egress, 3 = file, 4 = payment.
    pub kind: u8,
    /// First (big-endian) 128-bit SHA-256 digest limb.
    pub digest_hi: DigestLimb,
    /// Second (big-endian) 128-bit SHA-256 digest limb.
    pub digest_lo: DigestLimb,
}

/// A fixed-size statement as defined in SAR-ZK section 4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub profile_tag: FieldWire,
    pub task_binding: FieldWire,
    pub step_count: FieldWire,
    pub transcript: FieldWire,
    pub nk_commitment: FieldWire,
}

/// An explicitly uncompressed Pallas affine point. Both coordinates are
/// canonical little-endian Pallas base-field encodings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointWire {
    pub x: FieldWire,
    pub y: FieldWire,
}

/// Profile-B Schnorr signature `(R, s)`. `s` is a canonical little-endian
/// Pallas scalar-field encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature {
    pub r: PointWire,
    pub s: FieldWire,
}

/// The policy opening needed by the relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub allowlist_root: FieldWire,
    pub egress_allowed: bool,
    pub payment_bound: u32,
    /// Public policy commitment expected by the verifier.
    pub commitment: FieldWire,
}

/// One depth-16 allowlist membership witness for a tool entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPath {
    /// Index of the corresponding entry in [`Input::entries`].
    pub entry_index: u32,
    /// Index of this digest in the sorted duplicate-free allowlist.
    pub leaf_index: u32,
    pub siblings: [FieldWire; ALLOWLIST_DEPTH],
}

/// Deterministic-fixture facts the host should retain alongside a benchmark.
/// These are descriptive metadata, not relation inputs; [`verify`] never
/// trusts them for a cryptographic check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureMetadata {
    pub requested_t: u32,
    pub seed: [u8; 32],
    /// One kind byte per generated inventory entry.
    pub entry_kinds: Vec<u8>,
    pub payment_bound: u32,
    /// Number of elements in the sorted, duplicate-free fixture allowlist.
    pub tool_allowlist_size: u32,
    /// Number of populated leaves used to construct the fixture log root.
    pub log_tree_size: u32,
    /// The relation only proves membership in the supplied log tree. It cannot
    /// establish a real-world anonymity-set size.
    pub candidate_set_unknown: bool,
}

/// Complete private and public input to the native Profile-B relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// Public profile tag. It must be the canonical field encoding of 0x0b and
    /// must equal `statement.profile_tag`.
    pub profile_tag: FieldWire,
    /// Public commitment to the pinned issuer public key.
    pub issuer_key_commitment: FieldWire,
    pub statement: Statement,
    pub issuer_public_key: PointWire,
    pub signature: SchnorrSignature,
    pub entries: Vec<Entry>,
    pub policy: Policy,
    /// Exactly one path for each tool entry, in inventory order.
    pub tool_paths: Vec<ToolPath>,
    pub log_root: FieldWire,
    pub tree_size: u32,
    pub leaf_index: u32,
    pub log_path: [FieldWire; LOG_DEPTH],
    pub nk: FieldWire,
    pub r: FieldWire,
    pub nullifier_scope: FieldWire,
    /// The public nullifier expected by the verifier. It is checked, not just
    /// emitted, so an input cannot substitute a different nullifier.
    pub expected_nullifier: FieldWire,
    /// Present in memory for deterministic fixtures produced by [`generate`].
    /// It is intentionally skipped from input serialization: guest witnesses
    /// should not carry benchmark-only metadata.
    #[serde(skip)]
    pub fixture_metadata: Option<FixtureMetadata>,
}

/// The seven public values committed to the guest journal, in this exact
/// order: profile tag, issuer-key commitment, log root, tree size, policy
/// commitment, nullifier scope, nullifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub values: [FieldWire; 7],
}

/// Fixed outputs from boundary and deterministic-state Poseidon checks. This
/// is for a separate zkVM accelerator diagnostic, never for a receipt journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceleratorSelfTest {
    pub values: [FieldWire; 7],
}

/// Relation failures are intentionally specific enough for negative fixture
/// tests while revealing no additional data in a normal guest journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDomain,
    NonCanonicalField,
    NonCanonicalScalar,
    InvalidPoint,
    IdentityPoint,
    InvalidProfile,
    InvalidStepCount,
    InvalidPolicy,
    PolicyViolation,
    InvalidToolPath,
    InvalidLogPath,
    InvalidLogSize,
    TranscriptMismatch,
    NkCommitmentMismatch,
    InvalidSignature,
    NullifierMismatch,
    AcceleratorMismatch,
    FixtureTooShort,
    FixtureTooLarge,
}

/// Hash arbitrary canonical field wires using the SAR-ZK section 3.2 sponge.
/// The output is always a canonical little-endian Pallas base-field wire.
///
/// This is intentionally not `halo2_poseidon::Hash`: SAR-ZK defines its own
/// raw rate-two sponge framing (`tag(D), k, inputs...`) with a zero initial
/// state. The permutation and constants are exactly `P128Pow5T3` from
/// `halo2_poseidon` 0.2.0.
pub fn hash(domain: &str, input: &[FieldWire]) -> Result<FieldWire, Error> {
    let mut hasher = Poseidon::new();
    let mut fields = Vec::new();
    fields
        .try_reserve(input.len())
        .map_err(|_| Error::FixtureTooLarge)?;
    for wire in input {
        fields.push(fp_from_wire(wire)?);
    }
    Ok(fp_to_wire(hasher.hash_label(domain, &fields)?))
}

/// Exercise the selected Poseidon backend on fixed boundary values and return
/// seven deterministic outputs. Under either RISC0 acceleration guest feature,
/// this additionally checks limb arithmetic and permutation results against
/// the portable Pasta implementation before returning.
pub fn accelerator_self_test() -> Result<AcceleratorSelfTest, Error> {
    #[cfg(all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    ))]
    accelerated::self_test()?;
    #[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
    pallas_accelerated::self_test()?;
    accelerator_self_test_outputs()
}

fn accelerator_self_test_outputs() -> Result<AcceleratorSelfTest, Error> {
    let zero = Fp::ZERO;
    let one = Fp::ONE;
    let max = -Fp::ONE;
    let a = Fp::from(0x0123_4567_89ab_cdefu64);
    let b = Fp::from(0xfedc_ba98_7654_3210u64);
    let mut hasher = Poseidon::new();
    Ok(AcceleratorSelfTest {
        values: [
            fp_to_wire(hasher.hash_label(D_EMPTY, &[])?),
            fp_to_wire(hasher.hash_label(D_NODE, &[zero, zero])?),
            fp_to_wire(hasher.hash_label(D_NODE, &[one, max])?),
            fp_to_wire(hasher.hash_label(D_STEP, &[max, one, zero, Fp::from(3), a])?),
            fp_to_wire(hasher.hash_label(D_STATEMENT, &[Fp::from(PROFILE_B_TAG), a, b, one, max])?),
            fp_to_wire(hasher.hash_label(D_SCHNORR, &[a, b, max, one, zero])?),
            fp_to_wire(hasher.hash_label(D_POLICY, &[max, one, Fp::from(u32::MAX as u64)])?),
        ],
    })
}

/// A recorded deterministic seed suitable for repeatable local benchmark
/// fixtures. Real receipt issuance must use fresh unpredictable entropy.
pub const DEFAULT_FIXTURE_SEED: [u8; 32] = [
    0x53, 0x41, 0x52, 0x2d, 0x5a, 0x4b, 0x2d, 0x76, 0x30, 0x2e, 0x34, 0x62, 0x2d, 0x66, 0x69, 0x78,
    0x74, 0x75, 0x72, 0x65, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x30, 0x30, 0x30, 0x31, 0x21, 0x21,
];

/// Deterministically build a mixed native fixture from a ChaCha20 seed.
///
/// The fixture has a repeating tool/file/payment/egress shape (as many kinds
/// as fit in `t`). Every tool digest is distinct by default, the allowlist is
/// sorted and duplicate-free, and the log contains several populated leaves
/// in addition to this statement.
pub fn generate(t: usize, seed: [u8; 32]) -> Result<Input, Error> {
    if t == 0 {
        return Err(Error::FixtureTooShort);
    }
    if (t as u64) >= (1u64 << 32) {
        return Err(Error::FixtureTooLarge);
    }

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut hasher = Poseidon::new();

    let mut kinds = Vec::new();
    kinds.try_reserve(t).map_err(|_| Error::FixtureTooLarge)?;
    for index in 0..t {
        // Mixing all four kinds is intentional fixture coverage, not a policy
        // assertion about a production run.
        kinds.push(match index % 4 {
            0 => KIND_TOOL,
            1 => KIND_FILE,
            2 => KIND_PAYMENT,
            _ => KIND_EGRESS,
        });
    }

    let tool_count = kinds.iter().filter(|&&kind| kind == KIND_TOOL).count();
    let distinct_tool_count = tool_count;
    let mut tool_digests = Vec::new();
    tool_digests
        .try_reserve(distinct_tool_count)
        .map_err(|_| Error::FixtureTooLarge)?;
    while tool_digests.len() < distinct_tool_count {
        let digest = random_digest(&mut rng);
        if !tool_digests.contains(&digest) {
            tool_digests.push(digest);
        }
    }

    let mut allowlist = tool_digests.clone();
    allowlist.sort_unstable();
    allowlist.dedup();

    let mut entries = Vec::new();
    entries.try_reserve(t).map_err(|_| Error::FixtureTooLarge)?;
    let mut tool_cursor = 0usize;
    for &kind in &kinds {
        let (digest_hi, digest_lo) = if kind == KIND_TOOL {
            let digest = tool_digests[tool_cursor];
            tool_cursor += 1;
            digest
        } else {
            random_digest(&mut rng)
        };
        entries.push(Entry {
            kind,
            digest_hi,
            digest_lo,
        });
    }

    let mut allow_leaves = Vec::new();
    allow_leaves
        .try_reserve(allowlist.len())
        .map_err(|_| Error::FixtureTooLarge)?;
    for &(hi, lo) in &allowlist {
        allow_leaves.push(allow_leaf(&mut hasher, limb_to_fp(&hi), limb_to_fp(&lo))?);
    }
    let (allowlist_root, _) = tree_root_and_path(&mut hasher, &allow_leaves, 0, ALLOWLIST_DEPTH)?;

    let payment_count = kinds.iter().filter(|&&kind| kind == KIND_PAYMENT).count() as u32;
    // Permit this recorded run but leave a nonzero allowance for a different
    // valid payment count in relation tests.
    let payment_bound = payment_count.checked_add(1).ok_or(Error::FixtureTooLarge)?;
    let egress_allowed = true;
    let policy_commitment =
        policy_commitment(&mut hasher, allowlist_root, egress_allowed, payment_bound)?;

    let mut tool_paths = Vec::new();
    tool_paths
        .try_reserve(tool_count)
        .map_err(|_| Error::FixtureTooLarge)?;
    for (entry_index, entry) in entries.iter().enumerate() {
        if entry.kind != KIND_TOOL {
            continue;
        }
        let digest = (entry.digest_hi, entry.digest_lo);
        let leaf_index = allowlist
            .binary_search(&digest)
            .map_err(|_| Error::InvalidToolPath)?;
        let (root, siblings) =
            tree_root_and_path(&mut hasher, &allow_leaves, leaf_index, ALLOWLIST_DEPTH)?;
        if root != allowlist_root {
            return Err(Error::InvalidToolPath);
        }
        tool_paths.push(ToolPath {
            entry_index: entry_index as u32,
            leaf_index: leaf_index as u32,
            siblings: path_to_wire_array::<ALLOWLIST_DEPTH>(&siblings)?,
        });
    }

    let nk = random_base(&mut rng);
    let r = random_base(&mut rng);
    let task_binding = random_base(&mut rng);
    let parsed_entries = parse_entries(&entries)?;
    let transcript_value = transcript(&mut hasher, task_binding, &parsed_entries)?;
    let nk_commitment_value = nk_commitment(&mut hasher, nk, r)?;
    let profile_tag = Fp::from(PROFILE_B_TAG);
    let statement = Statement {
        profile_tag: fp_to_wire(profile_tag),
        task_binding: fp_to_wire(task_binding),
        step_count: fp_to_wire(Fp::from(t as u64)),
        transcript: fp_to_wire(transcript_value),
        nk_commitment: fp_to_wire(nk_commitment_value),
    };
    let parsed_statement = ParsedStatement {
        profile_tag,
        task_binding,
        step_count: Fp::from(t as u64),
        transcript: transcript_value,
        nk_commitment: nk_commitment_value,
    };
    let statement_hash = statement_hash(&mut hasher, &parsed_statement)?;

    let issuer_secret = random_scalar(&mut rng);
    let generator = pallas_generator()?;
    let issuer_public_key = (generator * issuer_secret).to_affine();
    let issuer_public_key_wire = point_to_wire(issuer_public_key)?;
    let issuer_key_commitment = issuer_key_commitment(
        &mut hasher,
        fp_from_wire(&issuer_public_key_wire.x)?,
        fp_from_wire(&issuer_public_key_wire.y)?,
    )?;

    let nonce = random_scalar(&mut rng);
    let r_point = (generator * nonce).to_affine();
    let r_wire = point_to_wire(r_point)?;
    let challenge = schnorr_challenge(
        &mut hasher,
        fp_from_wire(&r_wire.x)?,
        fp_from_wire(&r_wire.y)?,
        fp_from_wire(&issuer_public_key_wire.x)?,
        fp_from_wire(&issuer_public_key_wire.y)?,
        statement_hash,
    )?;
    let challenge_scalar = scalar_from_base(challenge)?;
    let signature = SchnorrSignature {
        r: r_wire,
        s: scalar_to_wire(nonce + challenge_scalar * issuer_secret),
    };

    // Populate a non-singleton log fixture. Its size does not establish an
    // anonymity-set size; metadata makes that limitation explicit.
    let log_count = cmp::max(8usize, t.checked_add(3).ok_or(Error::FixtureTooLarge)?);
    let mut log_leaves = Vec::new();
    log_leaves
        .try_reserve(log_count)
        .map_err(|_| Error::FixtureTooLarge)?;
    for _ in 0..log_count {
        let filler_hash = fixture_filler_statement_hash(&mut hasher, &mut rng)?;
        log_leaves.push(log_leaf(&mut hasher, filler_hash)?);
    }
    let leaf_index = (rng.next_u32() as usize) % log_count;
    log_leaves[leaf_index] = log_leaf(&mut hasher, statement_hash)?;
    let (log_root, log_path) = tree_root_and_path(&mut hasher, &log_leaves, leaf_index, LOG_DEPTH)?;

    let nullifier_scope = random_base(&mut rng);
    let expected_nullifier = nullifier(&mut hasher, nk, nullifier_scope)?;
    let metadata = FixtureMetadata {
        requested_t: t as u32,
        seed,
        entry_kinds: kinds,
        payment_bound,
        tool_allowlist_size: allowlist.len() as u32,
        log_tree_size: log_count as u32,
        candidate_set_unknown: true,
    };

    Ok(Input {
        profile_tag: fp_to_wire(profile_tag),
        issuer_key_commitment: fp_to_wire(issuer_key_commitment),
        statement,
        issuer_public_key: issuer_public_key_wire,
        signature,
        entries,
        policy: Policy {
            allowlist_root: fp_to_wire(allowlist_root),
            egress_allowed,
            payment_bound,
            commitment: fp_to_wire(policy_commitment),
        },
        tool_paths,
        log_root: fp_to_wire(log_root),
        tree_size: log_count as u32,
        leaf_index: leaf_index as u32,
        log_path: path_to_wire_array::<LOG_DEPTH>(&log_path)?,
        nk: fp_to_wire(nk),
        r: fp_to_wire(r),
        nullifier_scope: fp_to_wire(nullifier_scope),
        expected_nullifier: fp_to_wire(expected_nullifier),
        fixture_metadata: Some(metadata),
    })
}

impl Input {
    /// Convenience form of [`generate`].
    pub fn generate(t: usize, seed: [u8; 32]) -> Result<Self, Error> {
        generate(t, seed)
    }

    /// Read benchmark metadata without reaching into fixture construction
    /// details. Inputs received from a real issuer need not have this value.
    pub fn benchmark_metadata(&self) -> Option<&FixtureMetadata> {
        self.fixture_metadata.as_ref()
    }
}

/// Verify all Profile-B checks and return exactly seven public journal values.
pub fn verify(input: &Input) -> Result<Journal, Error> {
    let mut hasher = Poseidon::new();

    let public_profile_tag = fp_from_wire(&input.profile_tag)?;
    if public_profile_tag != Fp::from(PROFILE_B_TAG) {
        return Err(Error::InvalidProfile);
    }
    let statement = parse_statement(&input.statement)?;
    if statement.profile_tag != public_profile_tag {
        return Err(Error::InvalidProfile);
    }

    let (_, issuer_x, issuer_y) = point_from_wire(&input.issuer_public_key)?;
    let public_issuer_commitment = fp_from_wire(&input.issuer_key_commitment)?;
    if issuer_key_commitment(&mut hasher, issuer_x, issuer_y)? != public_issuer_commitment {
        return Err(Error::InvalidSignature);
    }

    let parsed_entries = parse_entries(&input.entries)?;
    let entry_count = parsed_entries.len();
    if entry_count == 0
        || (entry_count as u64) >= (1u64 << 32)
        || statement.step_count != Fp::from(entry_count as u64)
    {
        return Err(Error::InvalidStepCount);
    }

    let allowlist_root = fp_from_wire(&input.policy.allowlist_root)?;
    let public_policy_commitment = fp_from_wire(&input.policy.commitment)?;
    if policy_commitment(
        &mut hasher,
        allowlist_root,
        input.policy.egress_allowed,
        input.policy.payment_bound,
    )? != public_policy_commitment
    {
        return Err(Error::InvalidPolicy);
    }

    // Cache only an already-verified *identical* (digest, index, siblings)
    // witness. The keys borrow the input rather than copying each 512-byte
    // sibling array. Requiring byte-for-byte sibling equality preserves the
    // same membership claim while avoiding repeated Poseidon paths in fixtures
    // that legitimately revisit an allowed tool.
    let mut verified_tool_paths = BTreeSet::new();
    let mut path_cursor = 0usize;
    let mut payment_count = 0u32;
    for (entry_index, entry) in parsed_entries.iter().enumerate() {
        match entry.kind {
            KIND_TOOL => {
                let path = input
                    .tool_paths
                    .get(path_cursor)
                    .ok_or(Error::InvalidToolPath)?;
                path_cursor += 1;
                if path.entry_index != entry_index as u32
                    || path.leaf_index >= (1u32 << ALLOWLIST_DEPTH)
                {
                    return Err(Error::InvalidToolPath);
                }
                let cached = CachedToolPath {
                    digest_hi: &input.entries[entry_index].digest_hi,
                    digest_lo: &input.entries[entry_index].digest_lo,
                    leaf_index: path.leaf_index,
                    siblings: &path.siblings,
                };
                if !verified_tool_paths.contains(&cached) {
                    let leaf = allow_leaf(&mut hasher, entry.digest_hi, entry.digest_lo)?;
                    let root = climb(&mut hasher, leaf, &path.siblings, path.leaf_index as u64)?;
                    if root != allowlist_root {
                        return Err(Error::InvalidToolPath);
                    }
                    if verified_tool_paths.len() < MAX_CACHED_TOOL_PATHS {
                        verified_tool_paths.insert(cached);
                    }
                }
            }
            KIND_EGRESS if !input.policy.egress_allowed => return Err(Error::PolicyViolation),
            KIND_EGRESS => {}
            KIND_FILE => {}
            KIND_PAYMENT => {
                payment_count = payment_count.checked_add(1).ok_or(Error::PolicyViolation)?;
            }
            _ => return Err(Error::PolicyViolation),
        }
    }
    if path_cursor != input.tool_paths.len() || payment_count > input.policy.payment_bound {
        return Err(Error::PolicyViolation);
    }

    if transcript(&mut hasher, statement.task_binding, &parsed_entries)? != statement.transcript {
        return Err(Error::TranscriptMismatch);
    }

    let nk = fp_from_wire(&input.nk)?;
    let r = fp_from_wire(&input.r)?;
    if nk_commitment(&mut hasher, nk, r)? != statement.nk_commitment {
        return Err(Error::NkCommitmentMismatch);
    }

    let h_s = statement_hash(&mut hasher, &statement)?;
    verify_schnorr(&mut hasher, &input.issuer_public_key, &input.signature, h_s)?;

    if !(1..=MAX_TREE_SIZE).contains(&input.tree_size) || input.leaf_index >= input.tree_size {
        return Err(Error::InvalidLogSize);
    }
    let log_root = fp_from_wire(&input.log_root)?;
    let leaf = log_leaf(&mut hasher, h_s)?;
    if climb(&mut hasher, leaf, &input.log_path, input.leaf_index as u64)? != log_root {
        return Err(Error::InvalidLogPath);
    }

    let nullifier_scope = fp_from_wire(&input.nullifier_scope)?;
    let expected_nullifier = fp_from_wire(&input.expected_nullifier)?;
    let actual_nullifier = nullifier(&mut hasher, nk, nullifier_scope)?;
    if actual_nullifier != expected_nullifier {
        return Err(Error::NullifierMismatch);
    }

    Ok(Journal {
        values: [
            fp_to_wire(public_profile_tag),
            fp_to_wire(public_issuer_commitment),
            fp_to_wire(log_root),
            fp_to_wire(Fp::from(input.tree_size as u64)),
            fp_to_wire(public_policy_commitment),
            fp_to_wire(nullifier_scope),
            fp_to_wire(actual_nullifier),
        ],
    })
}

#[derive(Clone, Copy)]
struct ParsedStatement {
    profile_tag: Fp,
    task_binding: Fp,
    step_count: Fp,
    transcript: Fp,
    nk_commitment: Fp,
}

#[derive(Clone, Copy)]
struct ParsedEntry {
    kind: u8,
    digest_hi: Fp,
    digest_lo: Fp,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CachedToolPath<'a> {
    digest_hi: &'a DigestLimb,
    digest_lo: &'a DigestLimb,
    leaf_index: u32,
    siblings: &'a [FieldWire; ALLOWLIST_DEPTH],
}

/// A P128Pow5T3 permutation with constants constructed once per verification.
/// `halo2_poseidon` exposes the exact upstream constants but its public `Hash`
/// type has different Orchard constant-length framing, so SAR-ZK owns this
/// small spec-defined sponge wrapper.
struct Poseidon {
    #[cfg(not(all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    )))]
    round_constants: Vec<[Fp; 3]>,
    #[cfg(not(all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    )))]
    mds: Mds<Fp, 3>,
    #[cfg(all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    ))]
    accelerated: accelerated::Constants,
    // State after absorbing and permuting `(tag(D), arity)`. This is sound to
    // share only for the same domain and arity; every following pair is still
    // absorbed and permuted normally.
    prefixes: [[Option<[Fp; 3]>; MAX_CACHED_ARITY + 1]; DOMAIN_COUNT],
    // Exact ordered node pairs are safe to memoize: H_node has no hidden
    // context. This helps ordinary overlapping Merkle paths without relying
    // on a fixture's tool-distribution shape. The bounded cache is optional
    // optimization only and never changes verification semantics.
    nodes: BTreeMap<(FieldWire, FieldWire), Fp>,
}

impl Poseidon {
    fn new() -> Self {
        #[cfg(all(
            target_os = "zkvm",
            any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
        ))]
        {
            // Do not derive P128Pow5T3 constants inside the guest. The
            // accelerated backend references the checked-in canonical limb
            // tables directly.
            Self {
                accelerated: accelerated::Constants::new(),
                prefixes: [[None; MAX_CACHED_ARITY + 1]; DOMAIN_COUNT],
                nodes: BTreeMap::new(),
            }
        }
        #[cfg(not(all(
            target_os = "zkvm",
            any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
        )))]
        {
            // The portable native implementation remains the oracle for the
            // generated guest table and for the relation's ordinary tests.
            let (round_constants, mds, _) =
                <P128Pow5T3 as PoseidonSpec<Fp, 3, 2>>::constants();
            Self {
                round_constants,
                mds,
                prefixes: [[None; MAX_CACHED_ARITY + 1]; DOMAIN_COUNT],
                nodes: BTreeMap::new(),
            }
        }
    }

    fn hash_label(&mut self, domain: &str, input: &[Fp]) -> Result<Fp, Error> {
        let mut state = self.prefix_state(domain, input.len())?;
        for pair in input.chunks(2) {
            state[0] += pair[0];
            if pair.len() == 2 {
                state[1] += pair[1];
            }
            self.permute(&mut state);
        }
        Ok(state[0])
    }

    fn prefix_state(&mut self, domain: &str, arity: usize) -> Result<[Fp; 3], Error> {
        let slot = domain_slot(domain);
        if let Some(slot) = slot {
            if arity <= MAX_CACHED_ARITY {
                if let Some(state) = self.prefixes[slot][arity] {
                    return Ok(state);
                }
                let state = self.compute_prefix(domain, arity)?;
                self.prefixes[slot][arity] = Some(state);
                return Ok(state);
            }
        }
        self.compute_prefix(domain, arity)
    }

    fn compute_prefix(&self, domain: &str, arity: usize) -> Result<[Fp; 3], Error> {
        let arity = u64::try_from(arity).map_err(|_| Error::InvalidDomain)?;
        let mut state = [domain_tag(domain)?, Fp::from(arity), Fp::ZERO];
        self.permute(&mut state);
        Ok(state)
    }

    fn permute(&self, state: &mut [Fp; 3]) {
        #[cfg(all(
            target_os = "zkvm",
            any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
        ))]
        {
            self.accelerated.permute(state);
        }
        #[cfg(not(all(
            target_os = "zkvm",
            any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
        )))]
        {
            // P128Pow5T3: 8 full rounds around 56 partial rounds. This follows
            // halo2_poseidon's internal permutation exactly while keeping the
            // SAR-ZK sponge framing visible and auditable here.
            for round in 0..64 {
                if round < 4 || round >= 60 {
                    for index in 0..3 {
                        let value = state[index] + self.round_constants[round][index];
                        let value_squared = value.square();
                        state[index] = value_squared.square() * value;
                    }
                } else {
                    for index in 0..3 {
                        state[index] += self.round_constants[round][index];
                    }
                    let value_squared = state[0].square();
                    state[0] = value_squared.square() * state[0];
                }
                let old = *state;
                for row in 0..3 {
                    let mut sum = Fp::ZERO;
                    for column in 0..3 {
                        sum += self.mds[row][column] * old[column];
                    }
                    state[row] = sum;
                }
            }
        }
    }

    fn node_hash(&mut self, left: Fp, right: Fp) -> Result<Fp, Error> {
        // Use canonical wire keys, not a field's internal Montgomery form,
        // so ordering remains stable across architectures and crate versions.
        let key = (fp_to_wire(left), fp_to_wire(right));
        if let Some(found) = self.nodes.get(&key) {
            return Ok(*found);
        }
        let value = self.hash_label(D_NODE, &[left, right])?;
        if self.nodes.len() < MAX_CACHED_NODES {
            self.nodes.insert(key, value);
        }
        Ok(value)
    }
}

/// Canonical-limb implementation of the exact P128Pow5T3 permutation.
///
/// It is compiled for the selected zkVM backend and for native tests, where
/// `LimbFp::mul` deliberately uses portable Pasta arithmetic as an oracle.
#[cfg(any(
    test,
    all(
        target_os = "zkvm",
        any(feature = "risc0-accelerated", feature = "risc0-legacy-mul")
    )
))]
mod accelerated {
    use super::*;
    use super::poseidon_constants;
    #[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
    use risc0_bigint2::field::modmul_256;
    #[cfg(all(target_os = "zkvm", feature = "risc0-legacy-mul"))]
    use risc0_zkvm_platform::syscall::{bigint, sys_bigint};

    /// Pallas base-field modulus in little-endian u32 limbs.
    pub(super) const MODULUS: [u32; 8] = [
        0x0000_0001,
        0x992d_30ed,
        0x094c_f91b,
        0x2246_98fc,
        0,
        0,
        0,
        0x4000_0000,
    ];

    #[derive(Clone, Copy)]
    pub(super) struct LimbFp(pub(super) [u32; 8]);

    /// Convert Pasta's canonical wire encoding into bigint2's limb order.
    pub(super) fn canonical_limbs(value: Fp) -> [u32; 8] {
        let wire = fp_to_wire(value);
        core::array::from_fn(|index| {
            u32::from_le_bytes(
                wire[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("fixed Pallas wire length"),
            )
        })
    }

    impl LimbFp {
        pub(super) const ZERO: Self = Self([0; 8]);

        pub(super) fn from_fp(value: Fp) -> Self {
            Self(canonical_limbs(value))
        }

        pub(super) fn to_fp(self) -> Fp {
            let mut wire = [0u8; 32];
            for (index, word) in self.0.iter().enumerate() {
                wire[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            match fp_from_wire(&wire) {
                Ok(value) => value,
                Err(_) => unreachable!("checked bigint2 output is canonical"),
            }
        }

        pub(super) fn add(self, rhs: Self) -> Self {
            // Each canonical operand is < p < 2^255, so their sum does not
            // overflow 256 bits and needs at most one subtraction of p.
            let mut sum = [0u32; 8];
            let mut carry = 0u64;
            for index in 0..8 {
                let value = self.0[index] as u64 + rhs.0[index] as u64 + carry;
                sum[index] = value as u32;
                carry = value >> 32;
            }
            debug_assert_eq!(carry, 0);
            let (reduced, borrowed) = subtract(&sum, &MODULUS);
            if borrowed {
                Self(sum)
            } else {
                Self(reduced)
            }
        }

        pub(super) fn sub(self, rhs: Self) -> Self {
            let (difference, borrowed) = subtract(&self.0, &rhs.0);
            if !borrowed {
                return Self(difference);
            }
            // Here self < rhs, so self + p - rhs is already canonical.
            let (modulus_minus_rhs, modulus_borrowed) = subtract(&MODULUS, &rhs.0);
            debug_assert!(!modulus_borrowed);
            let (result, carry) = add_words(&self.0, &modulus_minus_rhs);
            debug_assert_eq!(carry, 0);
            Self(result)
        }

        pub(super) fn mul(self, rhs: Self) -> Self {
            #[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
            {
                let mut result = [0u32; 8];
                // The checked bigint2 wrapper constrains result < p, including
                // against a dishonest host; operands are canonical here.
                modmul_256(&self.0, &rhs.0, &MODULUS, &mut result);
                return Self(result);
            }
            #[cfg(all(target_os = "zkvm", feature = "risc0-legacy-mul"))]
            {
                let mut result = [0u32; 8];
                unsafe {
                    // The legacy fixed-256 accelerator computes (lhs * rhs)
                    // mod modulus. It does not itself promise a canonical
                    // response, so retain the explicit postcondition below.
                    sys_bigint(&mut result, bigint::OP_MULTIPLY, &self.0, &rhs.0, &MODULUS);
                }
                assert!(
                    less_than(&result, &MODULUS),
                    "non-canonical accelerator output"
                );
                return Self(result);
            }
            #[cfg(not(target_os = "zkvm"))]
            {
                // Test-only fallback: retain the exact portable field result
                // while exercising the canonical limb boundary shared by the
                // guest and the accelerated Schnorr checks.
                Self::from_fp(self.to_fp() * rhs.to_fp())
            }
        }

        fn pow5(self) -> Self {
            let square = self.mul(self);
            square.mul(square).mul(self)
        }
    }

    fn subtract(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], bool) {
        let mut output = [0u32; 8];
        let mut borrow = 0u64;
        for index in 0..8 {
            let lhs_word = lhs[index] as u64;
            let rhs_word = rhs[index] as u64 + borrow;
            output[index] = lhs_word.wrapping_sub(rhs_word) as u32;
            borrow = u64::from(lhs_word < rhs_word);
        }
        (output, borrow != 0)
    }

    fn add_words(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], u64) {
        let mut output = [0u32; 8];
        let mut carry = 0u64;
        for index in 0..8 {
            let value = lhs[index] as u64 + rhs[index] as u64 + carry;
            output[index] = value as u32;
            carry = value >> 32;
        }
        (output, carry)
    }

    #[cfg(all(target_os = "zkvm", feature = "risc0-legacy-mul"))]
    fn less_than(lhs: &[u32; 8], rhs: &[u32; 8]) -> bool {
        for index in (0..8).rev() {
            if lhs[index] != rhs[index] {
                return lhs[index] < rhs[index];
            }
        }
        false
    }

    /// A zero-sized handle for the embedded P128Pow5T3 limb tables.
    pub(super) struct Constants;

    impl Constants {
        pub(super) const fn new() -> Self {
            Self
        }

        pub(super) fn permute(&self, state: &mut [Fp; 3]) {
            // Conversion happens once at the permutation boundary (three
            // inputs and outputs), not for every field operation. Each guest
            // round reads its canonical [u32; 8] values from the embedded
            // table rather than deriving or converting constants at runtime.
            let mut fast = [
                LimbFp::from_fp(state[0]),
                LimbFp::from_fp(state[1]),
                LimbFp::from_fp(state[2]),
            ];
            for round in 0..64 {
                if round < 4 || round >= 60 {
                    for index in 0..3 {
                        fast[index] = fast[index]
                            .add(LimbFp(poseidon_constants::ROUND_CONSTANTS[round][index]))
                            .pow5();
                    }
                } else {
                    for index in 0..3 {
                        fast[index] = fast[index]
                            .add(LimbFp(poseidon_constants::ROUND_CONSTANTS[round][index]));
                    }
                    fast[0] = fast[0].pow5();
                }
                let old = fast;
                for row in 0..3 {
                    let mut sum = LimbFp::ZERO;
                    for column in 0..3 {
                        sum = sum.add(
                            LimbFp(poseidon_constants::MDS[row][column]).mul(old[column]),
                        );
                    }
                    fast[row] = sum;
                }
            }
            *state = [fast[0].to_fp(), fast[1].to_fp(), fast[2].to_fp()];
        }
    }

    pub(super) fn self_test() -> Result<(), Error> {
        let edges = [
            Fp::ZERO,
            Fp::ONE,
            -Fp::ONE,
            Fp::from(0x0123_4567_89ab_cdefu64),
            Fp::from(0xfedc_ba98_7654_3210u64),
        ];
        for lhs in edges {
            for rhs in edges {
                let lhs_fast = LimbFp::from_fp(lhs);
                let rhs_fast = LimbFp::from_fp(rhs);
                if lhs_fast.add(rhs_fast).to_fp() != lhs + rhs
                    || lhs_fast.sub(rhs_fast).to_fp() != lhs - rhs
                    || lhs_fast.mul(rhs_fast).to_fp() != lhs * rhs
                {
                    return Err(Error::AcceleratorMismatch);
                }
            }
        }
        Ok(())
    }
}

fn domain_slot(domain: &str) -> Option<usize> {
    match domain {
        D_STATEMENT => Some(0),
        D_LEAF => Some(1),
        D_NODE => Some(2),
        D_EMPTY => Some(3),
        D_TRANSCRIPT => Some(4),
        D_STEP => Some(5),
        D_ALLOW => Some(6),
        D_POLICY => Some(7),
        D_NK => Some(8),
        D_NULLIFIER => Some(9),
        D_ISSUER => Some(10),
        D_SCHNORR => Some(11),
        _ => None,
    }
}

fn domain_tag(domain: &str) -> Result<Fp, Error> {
    if domain.len() > 31 || !domain.is_ascii() {
        return Err(Error::InvalidDomain);
    }
    // `tag(D)` is a big-endian integer, while field wires are explicitly LE.
    let mut wire = [0u8; 32];
    for (destination, source) in wire.iter_mut().zip(domain.as_bytes().iter().rev()) {
        *destination = *source;
    }
    fp_from_wire(&wire)
}

fn fp_from_wire(wire: &FieldWire) -> Result<Fp, Error> {
    Option::<Fp>::from(Fp::from_repr(*wire)).ok_or(Error::NonCanonicalField)
}

fn fp_to_wire(value: Fp) -> FieldWire {
    value.to_repr()
}

fn scalar_from_wire(wire: &FieldWire) -> Result<Fq, Error> {
    Option::<Fq>::from(Fq::from_repr(*wire)).ok_or(Error::NonCanonicalScalar)
}

fn scalar_to_wire(value: Fq) -> FieldWire {
    value.to_repr()
}

fn scalar_from_base(value: Fp) -> Result<Fq, Error> {
    // The profile relies on p < q, so the canonical Fp representation is a
    // canonical scalar representation without reduction.
    scalar_from_wire(&fp_to_wire(value))
}

fn limb_to_fp(limb: &DigestLimb) -> Fp {
    Fp::from_u128(u128::from_be_bytes(*limb))
}

fn parse_statement(statement: &Statement) -> Result<ParsedStatement, Error> {
    Ok(ParsedStatement {
        profile_tag: fp_from_wire(&statement.profile_tag)?,
        task_binding: fp_from_wire(&statement.task_binding)?,
        step_count: fp_from_wire(&statement.step_count)?,
        transcript: fp_from_wire(&statement.transcript)?,
        nk_commitment: fp_from_wire(&statement.nk_commitment)?,
    })
}

fn parse_entries(entries: &[Entry]) -> Result<Vec<ParsedEntry>, Error> {
    let mut parsed = Vec::new();
    parsed
        .try_reserve(entries.len())
        .map_err(|_| Error::FixtureTooLarge)?;
    for entry in entries {
        match entry.kind {
            KIND_TOOL | KIND_EGRESS | KIND_FILE | KIND_PAYMENT => {}
            _ => return Err(Error::PolicyViolation),
        }
        parsed.push(ParsedEntry {
            kind: entry.kind,
            digest_hi: limb_to_fp(&entry.digest_hi),
            digest_lo: limb_to_fp(&entry.digest_lo),
        });
    }
    Ok(parsed)
}

fn statement_hash(hasher: &mut Poseidon, statement: &ParsedStatement) -> Result<Fp, Error> {
    hasher.hash_label(
        D_STATEMENT,
        &[
            statement.profile_tag,
            statement.task_binding,
            statement.step_count,
            statement.transcript,
            statement.nk_commitment,
        ],
    )
}

fn transcript(
    hasher: &mut Poseidon,
    task_binding: Fp,
    entries: &[ParsedEntry],
) -> Result<Fp, Error> {
    let mut value = hasher.hash_label(D_TRANSCRIPT, &[task_binding])?;
    for (index, entry) in entries.iter().enumerate() {
        value = hasher.hash_label(
            D_STEP,
            &[
                value,
                Fp::from((index + 1) as u64),
                Fp::from(entry.kind as u64),
                entry.digest_hi,
                entry.digest_lo,
            ],
        )?;
    }
    Ok(value)
}

fn nk_commitment(hasher: &mut Poseidon, nk: Fp, r: Fp) -> Result<Fp, Error> {
    hasher.hash_label(D_NK, &[nk, r])
}

fn nullifier(hasher: &mut Poseidon, nk: Fp, scope: Fp) -> Result<Fp, Error> {
    hasher.hash_label(D_NULLIFIER, &[nk, scope])
}

fn policy_commitment(
    hasher: &mut Poseidon,
    allowlist_root: Fp,
    egress_allowed: bool,
    payment_bound: u32,
) -> Result<Fp, Error> {
    hasher.hash_label(
        D_POLICY,
        &[
            allowlist_root,
            Fp::from(egress_allowed as u64),
            Fp::from(payment_bound as u64),
        ],
    )
}

fn issuer_key_commitment(hasher: &mut Poseidon, x: Fp, y: Fp) -> Result<Fp, Error> {
    hasher.hash_label(D_ISSUER, &[x, y])
}

fn schnorr_challenge(
    hasher: &mut Poseidon,
    r_x: Fp,
    r_y: Fp,
    pk_x: Fp,
    pk_y: Fp,
    message: Fp,
) -> Result<Fp, Error> {
    hasher.hash_label(D_SCHNORR, &[r_x, r_y, pk_x, pk_y, message])
}

fn allow_leaf(hasher: &mut Poseidon, digest_hi: Fp, digest_lo: Fp) -> Result<Fp, Error> {
    hasher.hash_label(D_ALLOW, &[digest_hi, digest_lo])
}

fn log_leaf(hasher: &mut Poseidon, statement_hash: Fp) -> Result<Fp, Error> {
    hasher.hash_label(D_LEAF, &[statement_hash])
}

fn node(hasher: &mut Poseidon, left: Fp, right: Fp) -> Result<Fp, Error> {
    hasher.node_hash(left, right)
}

fn climb(
    hasher: &mut Poseidon,
    mut value: Fp,
    siblings: &[FieldWire],
    index: u64,
) -> Result<Fp, Error> {
    for (level, sibling) in siblings.iter().enumerate() {
        let sibling = fp_from_wire(sibling)?;
        value = if ((index >> level) & 1) == 0 {
            node(hasher, value, sibling)?
        } else {
            node(hasher, sibling, value)?
        };
    }
    Ok(value)
}

fn point_from_wire(wire: &PointWire) -> Result<(pallas::Affine, Fp, Fp), Error> {
    let x = fp_from_wire(&wire.x)?;
    let y = fp_from_wire(&wire.y)?;
    let point = Option::<pallas::Affine>::from(<pallas::Affine as PastaCurveAffine>::from_xy(x, y))
        .ok_or(Error::InvalidPoint)?;
    if bool::from(point.is_identity()) {
        return Err(Error::IdentityPoint);
    }
    Ok((point, x, y))
}

fn point_to_wire(point: pallas::Affine) -> Result<PointWire, Error> {
    let coordinates = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
        <pallas::Affine as PastaCurveAffine>::coordinates(&point),
    )
    .ok_or(Error::IdentityPoint)?;
    Ok(PointWire {
        x: fp_to_wire(*coordinates.x()),
        y: fp_to_wire(*coordinates.y()),
    })
}

fn pallas_generator() -> Result<pallas::Affine, Error> {
    // SAR-ZK fixes G = (p - 1, 2), rather than relying on a library's opaque
    // generator choice.
    Option::<pallas::Affine>::from(<pallas::Affine as PastaCurveAffine>::from_xy(
        -Fp::ONE,
        Fp::from(2),
    ))
    .ok_or(Error::InvalidPoint)
}

fn verify_schnorr(
    hasher: &mut Poseidon,
    public_key_wire: &PointWire,
    signature: &SchnorrSignature,
    message: Fp,
) -> Result<(), Error> {
    let (public_key, pk_x, pk_y) = point_from_wire(public_key_wire)?;
    let (r, r_x, r_y) = point_from_wire(&signature.r)?;
    let s = scalar_from_wire(&signature.s)?;
    let challenge = schnorr_challenge(hasher, r_x, r_y, pk_x, pk_y, message)?;
    verify_schnorr_challenge(public_key, r, s, scalar_from_base(challenge)?)
}

fn verify_schnorr_challenge(
    public_key: pallas::Affine,
    r: pallas::Affine,
    s: Fq,
    challenge_scalar: Fq,
) -> Result<(), Error> {
    #[cfg(all(target_os = "zkvm", feature = "risc0-accelerated"))]
    {
        // Fairness fix 2: the two scalar multiplications run over the bigint2 curve
        // precompiles instead of portable Pasta arithmetic. Point and scalar
        // validity was already checked by the callers.
        return pallas_accelerated::verify_schnorr_challenge(
            public_key,
            r,
            s,
            challenge_scalar,
        );
    }
    #[cfg(not(all(target_os = "zkvm", feature = "risc0-accelerated")))]
    {
        let generator = pallas_generator()?;
        let left = generator * s;
        let right = r.to_curve() + public_key * challenge_scalar;
        if left == right {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

fn empty_subtrees(hasher: &mut Poseidon, depth: usize) -> Result<Vec<Fp>, Error> {
    let mut empty = Vec::new();
    empty
        .try_reserve(depth + 1)
        .map_err(|_| Error::FixtureTooLarge)?;
    empty.push(hasher.hash_label(D_EMPTY, &[])?);
    for level in 0..depth {
        empty.push(node(hasher, empty[level], empty[level])?);
    }
    Ok(empty)
}

fn tree_root_and_path(
    hasher: &mut Poseidon,
    leaves: &[Fp],
    index: usize,
    depth: usize,
) -> Result<(Fp, Vec<Fp>), Error> {
    let capacity = 1u64
        .checked_shl(depth as u32)
        .ok_or(Error::FixtureTooLarge)?;
    if leaves.len() as u64 > capacity || index as u64 >= capacity {
        return Err(Error::FixtureTooLarge);
    }
    let empty = empty_subtrees(hasher, depth)?;
    if depth == 0 {
        return Ok((leaves.first().copied().unwrap_or(empty[0]), Vec::new()));
    }
    let mut level = leaves.to_vec();
    let mut current_index = index;
    let mut path = Vec::new();
    path.try_reserve(depth)
        .map_err(|_| Error::FixtureTooLarge)?;
    for level_index in 0..depth {
        let sibling_index = current_index ^ 1;
        path.push(*level.get(sibling_index).unwrap_or(&empty[level_index]));
        let mut next = Vec::new();
        next.try_reserve(level.len().div_ceil(2))
            .map_err(|_| Error::FixtureTooLarge)?;
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 {
                pair[1]
            } else {
                empty[level_index]
            };
            next.push(node(hasher, pair[0], right)?);
        }
        if next.is_empty() {
            next.push(empty[level_index + 1]);
        }
        level = next;
        current_index >>= 1;
    }
    Ok((level[0], path))
}

fn path_to_wire_array<const N: usize>(path: &[Fp]) -> Result<[FieldWire; N], Error> {
    if path.len() != N {
        return Err(Error::InvalidLogPath);
    }
    let mut wire = [[0u8; 32]; N];
    for (destination, source) in wire.iter_mut().zip(path) {
        *destination = fp_to_wire(*source);
    }
    Ok(wire)
}

fn random_base(rng: &mut ChaCha20Rng) -> Fp {
    loop {
        let mut wire = [0u8; 32];
        rng.fill_bytes(&mut wire);
        if let Some(value) = Option::<Fp>::from(Fp::from_repr(wire)) {
            return value;
        }
    }
}

fn random_scalar(rng: &mut ChaCha20Rng) -> Fq {
    loop {
        let mut wire = [0u8; 32];
        rng.fill_bytes(&mut wire);
        if let Some(value) = Option::<Fq>::from(Fq::from_repr(wire)) {
            // Secret keys and nonces are sampled from [1, q - 1].
            if value != Fq::ZERO {
                return value;
            }
        }
    }
}

fn random_digest(rng: &mut ChaCha20Rng) -> (DigestLimb, DigestLimb) {
    let mut digest = [0u8; 32];
    rng.fill_bytes(&mut digest);
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&digest[..16]);
    lo.copy_from_slice(&digest[16..]);
    (hi, lo)
}

/// Construct a syntactically valid one-entry statement hash for a populated
/// fixture-log slot. It intentionally has no relation to the receipt being
/// verified and carries no claim about an external issuer or anonymity set.
fn fixture_filler_statement_hash(
    hasher: &mut Poseidon,
    rng: &mut ChaCha20Rng,
) -> Result<Fp, Error> {
    let (digest_hi, digest_lo) = random_digest(rng);
    let entry = ParsedEntry {
        kind: KIND_FILE,
        digest_hi: limb_to_fp(&digest_hi),
        digest_lo: limb_to_fp(&digest_lo),
    };
    let task_binding = random_base(rng);
    let entries = [entry];
    let transcript = transcript(hasher, task_binding, &entries)?;
    let nk_commitment = nk_commitment(hasher, random_base(rng), random_base(rng))?;
    statement_hash(
        hasher,
        &ParsedStatement {
            profile_tag: Fp::from(PROFILE_B_TAG),
            task_binding,
            step_count: Fp::from(1),
            transcript,
            nk_commitment,
        },
    )
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use halo2_poseidon::test_only_permute;

    const TEST_SEED: [u8; 32] = [0x5a; 32];

    fn different_field(wire: FieldWire) -> FieldWire {
        let zero = fp_to_wire(Fp::ZERO);
        if wire == zero {
            fp_to_wire(Fp::ONE)
        } else {
            zero
        }
    }

    /// Independently applies halo2_poseidon's exposed test permutation. This
    /// checks both P128Pow5T3 and SAR-ZK's raw two-at-a-time sponge framing.
    fn halo2_raw_sponge(domain: &str, inputs: &[Fp]) -> Fp {
        let (round_constants, mds, _) = <P128Pow5T3 as PoseidonSpec<Fp, 3, 2>>::constants();
        let mut state = [Fp::ZERO; 3];
        let mut absorb = Vec::new();
        absorb.push(domain_tag(domain).unwrap());
        absorb.push(Fp::from(inputs.len() as u64));
        absorb.extend_from_slice(inputs);
        for pair in absorb.chunks(2) {
            state[0] += pair[0];
            if pair.len() == 2 {
                state[1] += pair[1];
            }
            test_only_permute::<Fp, P128Pow5T3, 3, 2>(&mut state, &mds, &round_constants);
        }
        state[0]
    }

    fn canonical_limbs(value: Fp) -> [u32; 8] {
        let wire = fp_to_wire(value);
        core::array::from_fn(|index| {
            u32::from_le_bytes(
                wire[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("fixed Pallas wire length"),
            )
        })
    }

    #[test]
    fn embedded_poseidon_constants_match_spec() {
        let (round_constants, mds, _) = <P128Pow5T3 as PoseidonSpec<Fp, 3, 2>>::constants();

        assert_eq!(poseidon_constants::ROUND_CONSTANTS.len(), round_constants.len());
        for round in 0..round_constants.len() {
            for column in 0..3 {
                assert_eq!(
                    poseidon_constants::ROUND_CONSTANTS[round][column],
                    canonical_limbs(round_constants[round][column]),
                    "round constant at ({round}, {column})"
                );
            }
        }

        for row in 0..3 {
            for column in 0..3 {
                assert_eq!(
                    poseidon_constants::MDS[row][column],
                    canonical_limbs(mds[row][column]),
                    "MDS value at ({row}, {column})"
                );
            }
        }
    }

    #[test]
    fn embedded_limb_permutation_matches_spec() {
        let (round_constants, mds, _) = <P128Pow5T3 as PoseidonSpec<Fp, 3, 2>>::constants();
        let mut embedded = [
            Fp::from(0x0123_4567_89ab_cdefu64),
            Fp::from(0xfedc_ba98_7654_3210u64),
            -Fp::ONE,
        ];
        let mut expected = embedded;

        accelerated::Constants::new().permute(&mut embedded);
        test_only_permute::<Fp, P128Pow5T3, 3, 2>(&mut expected, &mds, &round_constants);
        assert_eq!(embedded, expected);
    }

    #[test]
    fn profile_hash_matches_halo2_p128pow5t3_permutation() {
        let wires = [
            fp_to_wire(Fp::from(7)),
            fp_to_wire(Fp::from(11)),
            fp_to_wire(Fp::from(19)),
            fp_to_wire(Fp::from(23)),
            fp_to_wire(Fp::from(29)),
        ];
        let fields: Vec<Fp> = wires
            .iter()
            .map(|wire| fp_from_wire(wire).unwrap())
            .collect();
        let expected = halo2_raw_sponge(D_STEP, &fields);
        let actual = fp_from_wire(&hash(D_STEP, &wires).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn generated_fixture_verifies_and_has_exact_journal_layout() {
        let input = generate(12, TEST_SEED).unwrap();
        let journal = verify(&input).unwrap();
        assert_eq!(journal.values.len(), 7);
        assert_eq!(journal.values[0], input.profile_tag);
        assert_eq!(journal.values[1], input.issuer_key_commitment);
        assert_eq!(journal.values[2], input.log_root);
        assert_eq!(journal.values[4], input.policy.commitment);
        assert_eq!(journal.values[5], input.nullifier_scope);
        assert_eq!(journal.values[6], input.expected_nullifier);

        let metadata = input.benchmark_metadata().unwrap();
        assert_eq!(metadata.requested_t, 12);
        assert_eq!(metadata.seed, TEST_SEED);
        assert!(metadata.candidate_set_unknown);
        assert_eq!(
            metadata.entry_kinds,
            vec![1, 3, 4, 2, 1, 3, 4, 2, 1, 3, 4, 2]
        );
    }

    #[test]
    fn generator_is_deterministic_and_supports_a_single_entry() {
        let first = generate(1, DEFAULT_FIXTURE_SEED).unwrap();
        let second = Input::generate(1, DEFAULT_FIXTURE_SEED).unwrap();
        assert_eq!(first, second);
        assert_eq!(verify(&first), verify(&second));
        assert!(verify(&first).is_ok());
    }

    #[test]
    fn accelerator_diagnostic_has_stable_seven_value_contract() {
        let first = accelerator_self_test().unwrap();
        let second = accelerator_self_test().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.values.len(), 7);
    }

    #[test]
    fn serde_round_trip_keeps_relation_but_omits_fixture_metadata() {
        let input = generate(8, TEST_SEED).unwrap();
        let encoded = serde_json::to_vec(&input).unwrap();
        let decoded: Input = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.benchmark_metadata().is_none());
        assert_eq!(verify(&input).unwrap(), verify(&decoded).unwrap());
    }

    #[test]
    fn malformed_fields_and_ranges_are_rejected() {
        let input = generate(8, TEST_SEED).unwrap();

        let mut noncanonical = input.clone();
        noncanonical.profile_tag = [0xff; 32];
        assert_eq!(verify(&noncanonical), Err(Error::NonCanonicalField));

        let mut scalar = input.clone();
        scalar.signature.s = [0xff; 32];
        assert_eq!(verify(&scalar), Err(Error::NonCanonicalScalar));

        let mut no_tree = input;
        no_tree.tree_size = 0;
        assert_eq!(verify(&no_tree), Err(Error::InvalidLogSize));
    }

    #[test]
    fn transcript_signature_policy_path_and_nullifier_mutations_are_rejected() {
        let input = generate(12, TEST_SEED).unwrap();

        let mut wrong_tool = input.clone();
        wrong_tool.entries[0].digest_hi[0] ^= 1;
        assert_eq!(verify(&wrong_tool), Err(Error::InvalidToolPath));

        let mut wrong_transcript = input.clone();
        wrong_transcript.statement.transcript =
            different_field(wrong_transcript.statement.transcript);
        assert_eq!(verify(&wrong_transcript), Err(Error::TranscriptMismatch));

        let mut wrong_signature = input.clone();
        wrong_signature.signature.s = different_field(wrong_signature.signature.s);
        assert_eq!(verify(&wrong_signature), Err(Error::InvalidSignature));

        let mut wrong_log_path = input.clone();
        wrong_log_path.log_path[0] = different_field(wrong_log_path.log_path[0]);
        assert_eq!(verify(&wrong_log_path), Err(Error::InvalidLogPath));

        let mut wrong_nullifier = input;
        wrong_nullifier.expected_nullifier = different_field(wrong_nullifier.expected_nullifier);
        assert_eq!(verify(&wrong_nullifier), Err(Error::NullifierMismatch));
    }

    #[test]
    fn tool_path_cache_bound_does_not_skip_later_witnesses() {
        // There is one tool every four fixture entries. Fill the cache with
        // valid, distinct paths, then make the next one invalid.
        let mut input = generate(MAX_CACHED_TOOL_PATHS * 4 + 1, TEST_SEED).unwrap();
        assert_eq!(input.tool_paths.len(), MAX_CACHED_TOOL_PATHS + 1);
        let last_path = input.tool_paths.last_mut().unwrap();
        last_path.siblings[0] = different_field(last_path.siblings[0]);
        assert_eq!(verify(&input), Err(Error::InvalidToolPath));
    }
}
