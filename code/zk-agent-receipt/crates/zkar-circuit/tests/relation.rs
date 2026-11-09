//! Tests for the SAR-ZK v0.4 relation mirror. Each test changes one thing an
//! attacker controls and checks that the relation refuses it.

use zkar_circuit::*;

type F = PlaceholderField;
type H = TestHasher;

const TOOL_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOOL_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TOOL_X: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PAY: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OUT: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn e(kind: Kind, d: &str) -> Entry<F> {
    Entry::from_digest(kind, d).unwrap()
}

/// A complete honest instance. Fields are public so tests can tamper.
struct Fixture {
    entries: Vec<Entry<F>>,
    allow_paths: Vec<(u64, Vec<F>)>,
    policy: PolicyOpening<F>,
    statement: Statement<F>,
    leaf_index: u64,
    log_path: Vec<F>,
    public: Public<F>,
    nk: F,
    r: F,
    other_leaves: Vec<F>,
}

fn allowlist() -> Vec<Entry<F>> {
    vec![e(Kind::Tool, TOOL_A), e(Kind::Tool, TOOL_B)]
}

fn build(entries: Vec<Entry<F>>, egress_allowed: bool, payment_bound: u64) -> Fixture {
    let allow = allowlist();
    let allow_leaves: Vec<F> = allow.iter().map(allow_leaf::<H>).collect();
    let allowlist_root = tree_root::<H>(&allow_leaves, ALLOWLIST_DEPTH);
    let mut allow_paths = vec![];
    for en in entries.iter().filter(|en| en.kind == Kind::Tool) {
        let idx = allow.iter().position(|a| a == en).unwrap_or(0);
        let (_, path) = tree_root_and_path::<H>(&allow_leaves, idx, ALLOWLIST_DEPTH);
        allow_paths.push((idx as u64, path));
    }
    let policy = PolicyOpening { allowlist_root, egress_allowed, payment_bound };
    let nk = F::from_u64(0xdead);
    let r = F::from_u64(0xbeef);
    let task_binding = F::from_u64(77);
    let statement = Statement {
        profile_tag: F::from_u64(0x0b),
        task_binding,
        step_count: F::from_u64(entries.len() as u64),
        transcript: transcript::<H>(task_binding, &entries),
        nk_commitment: nk_commitment::<H>(nk, r),
    };
    // A log with 5 leaves; ours sits at index 3.
    let other_leaves: Vec<F> = (0..5).map(|i| log_leaf::<H>(F::from_u64(1000 + i))).collect();
    let mut leaves = other_leaves.clone();
    leaves[3] = log_leaf::<H>(statement.h_s::<H>());
    let (root, log_path) = tree_root_and_path::<H>(&leaves, 3, LOG_DEPTH);
    let scope = F::from_u64(42);
    let public = Public {
        profile_tag: F::from_u64(0x0b),
        log_root: root,
        tree_size: 5,
        policy_commitment: policy_commitment::<H>(allowlist_root, egress_allowed, payment_bound),
        nullifier_scope: scope,
        nullifier: nullifier::<H>(nk, scope),
    };
    Fixture { entries, allow_paths, policy, statement, leaf_index: 3, log_path, public, nk, r, other_leaves }
}

fn holds(f: &Fixture) -> bool {
    let w = Witness {
        statement: f.statement,
        entries: &f.entries,
        allow_paths: &f.allow_paths,
        policy: f.policy,
        leaf_index: f.leaf_index,
        log_path: &f.log_path,
        nk: f.nk,
        r: f.r,
    };
    relation_holds::<H>(&f.public, &w)
}

fn run() -> Vec<Entry<F>> {
    vec![e(Kind::Tool, TOOL_A), e(Kind::Payment, PAY), e(Kind::Tool, TOOL_B), e(Kind::File, OUT)]
}

#[test]
fn honest_run_holds() {
    assert!(holds(&build(run(), false, 1)));
}

#[test]
fn changed_entry_breaks_the_transcript() {
    let mut f = build(run(), false, 1);
    f.entries[3] = e(Kind::File, PAY);
    assert!(!holds(&f));
}

#[test]
fn dropped_entry_cannot_prove_a_prefix() {
    let mut f = build(run(), false, 1);
    f.entries.pop();
    assert!(!holds(&f));
    // Even with step_count fixed up, the signed transcript does not match.
    f.statement.step_count = F::from_u64(3);
    assert!(!holds(&f));
}

#[test]
fn reordered_entries_break_the_transcript() {
    let mut f = build(run(), false, 1);
    f.entries.swap(1, 3);
    assert!(!holds(&f));
}

#[test]
fn tool_off_the_allowlist_is_refused() {
    let mut entries = run();
    entries.push(e(Kind::Tool, TOOL_X));
    assert!(!holds(&build(entries, false, 1)));
}

#[test]
fn egress_needs_the_egress_flag() {
    let mut entries = run();
    entries.push(e(Kind::Egress, OUT));
    assert!(!holds(&build(entries.clone(), false, 1)));
    assert!(holds(&build(entries, true, 1)));
}

#[test]
fn payments_over_the_bound_are_refused() {
    let mut entries = run();
    entries.push(e(Kind::Payment, PAY));
    assert!(!holds(&build(entries.clone(), false, 1)));
    assert!(holds(&build(entries, false, 2)));
}

#[test]
fn wrong_policy_commitment_is_refused() {
    let mut f = build(run(), false, 1);
    f.policy.payment_bound = 9; // prover claims a looser policy than the verifier pinned
    assert!(!holds(&f));
}

#[test]
fn wrong_nk_opening_is_refused() {
    let mut f = build(run(), false, 1);
    f.nk = F::from_u64(1);
    assert!(!holds(&f));
}

#[test]
fn nullifier_ignores_log_position_and_separates_scopes() {
    let nk = F::from_u64(0xdead);
    // The nullifier takes no log position, so a second copy of the same
    // statement in the log cannot produce a second value.
    assert_eq!(nullifier::<H>(nk, F::from_u64(42)), nullifier::<H>(nk, F::from_u64(42)));
    assert_ne!(nullifier::<H>(nk, F::from_u64(42)), nullifier::<H>(nk, F::from_u64(43)));
    // A nullifier for a different scope fails the relation.
    let mut f = build(run(), false, 1);
    f.public.nullifier = nullifier::<H>(nk, F::from_u64(43));
    assert!(!holds(&f));
}

#[test]
fn leaf_index_must_be_below_tree_size() {
    let mut f = build(run(), false, 1);
    f.public.tree_size = 3; // leaf_index is 3
    assert!(!holds(&f));
}

#[test]
fn short_path_and_internal_node_are_refused() {
    let f = build(run(), false, 1);
    let h_s = f.statement.h_s::<H>();
    assert!(log_member::<H>(h_s, &f.log_path, 3, 5, f.public.log_root));
    // A path of the wrong length fails.
    assert!(!log_member::<H>(h_s, &f.log_path[..31], 3, 5, f.public.log_root));
    // An internal node offered as a leaf fails: the leaf is re-hashed under
    // its own label, so the climb starts from a different value.
    let node = TestHasher::hash("SAR-ZK node", &[f.other_leaves[0], f.other_leaves[1]]);
    let (root, path) = tree_root_and_path::<H>(&f.other_leaves, 0, LOG_DEPTH);
    let mut shifted: Vec<F> = path[1..].to_vec();
    shifted.push(empty_subtrees::<H>(LOG_DEPTH)[LOG_DEPTH]);
    assert!(!log_member::<H>(node, &shifted, 0, 5, root));
}

#[test]
fn statement_profile_must_match_the_receipt_profile() {
    let mut f = build(run(), false, 1);
    f.public.profile_tag = F::from_u64(0x0a); // receipt says profile a, statement says b
    assert!(!holds(&f));
}

#[test]
fn tree_builder_refuses_overfull_trees() {
    let leaves: Vec<F> = (0..9).map(F::from_u64).collect();
    let r = std::panic::catch_unwind(|| tree_root::<H>(&leaves, 3));
    assert!(r.is_err(), "9 leaves in a depth-3 tree must not silently drop one");
    assert_eq!(tree_root::<H>(&[], 0), empty_subtrees::<H>(0)[0]);
}

#[test]
fn allowlist_root_is_order_independent() {
    use zkar_core::policy::Policy;
    let p1 = Policy::new(vec![TOOL_A.into(), TOOL_B.into()], false, 1).unwrap();
    let p2 = Policy::new(vec![TOOL_B.into(), TOOL_A.into()], false, 1).unwrap();
    assert_eq!(allowlist_root::<H>(&p1), allowlist_root::<H>(&p2));
}

#[test]
fn empty_run_is_refused() {
    assert!(!holds(&build(vec![], false, 1)));
}

#[test]
fn digest_limbs_reject_bad_digests() {
    assert!(digest_limbs("sha256:00").is_none());
    assert!(digest_limbs(&TOOL_A.to_uppercase()).is_none());
    assert!(digest_limbs(TOOL_A).is_some());
}
