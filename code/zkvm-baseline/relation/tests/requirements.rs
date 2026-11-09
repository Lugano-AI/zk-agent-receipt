//! Adversarial requirements coverage for the public relation API.
//!
//! These tests intentionally mutate a valid deterministic fixture.  Where a
//! policy mutation is itself semantically valid, the public policy commitment
//! is recomputed first so the test reaches the intended policy rule.

use relation::{Error, FieldWire, Input, PointWire};

const TEST_T: usize = 12;

fn valid_input() -> Input {
    relation::generate(TEST_T, relation::DEFAULT_FIXTURE_SEED).expect("fixture generation")
}

fn field_u64(value: u64) -> FieldWire {
    let mut wire = [0u8; 32];
    wire[..8].copy_from_slice(&value.to_le_bytes());
    wire
}

fn wire_from_u64_limbs(limbs: [u64; 4]) -> FieldWire {
    let mut wire = [0u8; 32];
    for (slot, limb) in wire.chunks_exact_mut(8).zip(limbs) {
        slot.copy_from_slice(&limb.to_le_bytes());
    }
    wire
}

fn pallas_base_modulus() -> FieldWire {
    // p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
    wire_from_u64_limbs([
        0x992d_30ed_0000_0001,
        0x2246_98fc_094c_f91b,
        0,
        0x4000_0000_0000_0000,
    ])
}

fn pallas_scalar_modulus() -> FieldWire {
    // q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
    wire_from_u64_limbs([
        0x8c46_eb21_0000_0001,
        0x2246_98fc_0994_a8dd,
        0,
        0x4000_0000_0000_0000,
    ])
}

fn recompute_policy_commitment(input: &mut Input) {
    input.policy.commitment = relation::hash(
        "SAR-ZK policy",
        &[
            input.policy.allowlist_root,
            field_u64(input.policy.egress_allowed as u64),
            field_u64(input.policy.payment_bound as u64),
        ],
    )
    .expect("canonical policy fields");
}

fn assert_rejected(input: &Input, expected: Error) {
    assert_eq!(relation::verify(input), Err(expected));
}

#[test]
fn exact_p_and_q_encodings_are_rejected() {
    let mut base_modulus = valid_input();
    base_modulus.profile_tag = pallas_base_modulus();
    assert_rejected(&base_modulus, Error::NonCanonicalField);

    let mut scalar_modulus = valid_input();
    scalar_modulus.signature.s = pallas_scalar_modulus();
    assert_rejected(&scalar_modulus, Error::NonCanonicalScalar);
}

#[test]
fn public_and_statement_profile_tags_must_agree_with_profile_b() {
    let mut wrong_public = valid_input();
    wrong_public.profile_tag = field_u64(0);
    assert_rejected(&wrong_public, Error::InvalidProfile);

    let mut mismatched_statement = valid_input();
    mismatched_statement.statement.profile_tag = field_u64(relation::PROFILE_B_TAG + 1);
    assert_rejected(&mismatched_statement, Error::InvalidProfile);
}

#[test]
fn issuer_commitment_mismatch_is_rejected_before_signature_work() {
    let mut input = valid_input();
    let replacement = field_u64(0);
    assert_ne!(input.issuer_key_commitment, replacement);
    input.issuer_key_commitment = replacement;
    assert_rejected(&input, Error::InvalidSignature);
}

#[test]
fn identity_and_off_curve_points_are_rejected() {
    let mut identity = valid_input();
    identity.issuer_public_key = PointWire {
        x: [0; 32],
        y: [0; 32],
    };
    assert_rejected(&identity, Error::IdentityPoint);

    let mut off_curve = valid_input();
    off_curve.signature.r = PointWire {
        x: field_u64(0),
        y: field_u64(1),
    };
    assert_rejected(&off_curve, Error::InvalidPoint);
}

#[test]
fn payment_bound_is_enforced_after_a_valid_policy_recommitment() {
    let mut input = valid_input();
    let payment_count = input.entries.iter().filter(|entry| entry.kind == 4).count() as u32;
    assert!(payment_count > 0);
    input.policy.payment_bound = payment_count - 1;
    recompute_policy_commitment(&mut input);
    assert_rejected(&input, Error::PolicyViolation);
}

#[test]
fn egress_denial_is_enforced_after_a_valid_policy_recommitment() {
    let mut input = valid_input();
    assert!(input.entries.iter().any(|entry| entry.kind == 2));
    input.policy.egress_allowed = false;
    recompute_policy_commitment(&mut input);
    assert_rejected(&input, Error::PolicyViolation);
}

#[test]
fn unknown_and_padding_entry_kinds_are_rejected() {
    for kind in [0, 5, u8::MAX] {
        let mut input = valid_input();
        input.entries[0].kind = kind;
        assert_rejected(&input, Error::PolicyViolation);
    }
}

#[test]
fn allowlist_index_65536_is_rejected() {
    let mut input = valid_input();
    assert!(!input.tool_paths.is_empty());
    input.tool_paths[0].leaf_index = 1u32 << relation::ALLOWLIST_DEPTH;
    assert_rejected(&input, Error::InvalidToolPath);
}

#[test]
fn missing_and_extra_tool_paths_are_rejected() {
    let mut missing = valid_input();
    assert!(missing.tool_paths.pop().is_some());
    assert_rejected(&missing, Error::InvalidToolPath);

    let mut extra = valid_input();
    let duplicate = extra
        .tool_paths
        .first()
        .expect("fixture has a tool path")
        .clone();
    extra.tool_paths.push(duplicate);
    assert_rejected(&extra, Error::PolicyViolation);
}

#[test]
fn cached_tool_paths_require_the_full_identical_witness() {
    let mut exact_duplicate = valid_input();
    assert_eq!(exact_duplicate.tool_paths[0].entry_index, 0);
    assert_eq!(exact_duplicate.tool_paths[1].entry_index, 4);

    // Make the second tool repeat the first tool's exact allowlist witness.
    // The cache may reuse this membership check; the unchanged transcript
    // still records a different second entry and therefore fails afterward.
    exact_duplicate.entries[4].digest_hi = exact_duplicate.entries[0].digest_hi;
    exact_duplicate.entries[4].digest_lo = exact_duplicate.entries[0].digest_lo;
    exact_duplicate.tool_paths[1].leaf_index = exact_duplicate.tool_paths[0].leaf_index;
    exact_duplicate.tool_paths[1].siblings = exact_duplicate.tool_paths[0].siblings;
    assert_rejected(&exact_duplicate, Error::TranscriptMismatch);

    // A changed sibling must not hit that cache entry, even when the digest
    // and allowlist index match. It has to fail at membership before reaching
    // the intentionally stale transcript.
    let mut different_sibling = exact_duplicate;
    let sibling = different_sibling.tool_paths[1].siblings[0];
    different_sibling.tool_paths[1].siblings[0] = if sibling == field_u64(0) {
        field_u64(1)
    } else {
        field_u64(0)
    };
    assert_rejected(&different_sibling, Error::InvalidToolPath);
}

#[test]
fn zero_and_2_to_the_32_step_counts_are_rejected() {
    let mut zero = valid_input();
    zero.statement.step_count = field_u64(0);
    assert_rejected(&zero, Error::InvalidStepCount);

    let mut too_large = valid_input();
    too_large.statement.step_count = field_u64(1u64 << 32);
    assert_rejected(&too_large, Error::InvalidStepCount);
}

#[test]
fn invalid_log_tree_ranges_are_rejected_before_path_use() {
    let mut too_large_tree = valid_input();
    too_large_tree.tree_size = relation::MAX_TREE_SIZE + 1;
    assert_rejected(&too_large_tree, Error::InvalidLogSize);

    let mut leaf_out_of_range = valid_input();
    leaf_out_of_range.leaf_index = leaf_out_of_range.tree_size;
    assert_rejected(&leaf_out_of_range, Error::InvalidLogSize);
}
