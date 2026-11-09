//! attack2: relation_holds attacks. Convention: assertions state the defence;
//! a failure printed "GOT THROUGH" is a finding.

use zkar_circuit::*;

type F = PlaceholderField;
type H = TestHasher;

fn d(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn e(kind: Kind, c: char) -> Entry<F> {
    Entry::from_digest(kind, &d(c)).unwrap()
}

struct Inst {
    entries: Vec<Entry<F>>,
    allow: Vec<Entry<F>>,
    allow_paths: Vec<(u64, Vec<F>)>,
    policy: PolicyOpening<F>,
    statement: Statement<F>,
    leaf_index: u64,
    log_path: Vec<F>,
    public: Public<F>,
    nk: F,
    r: F,
}

fn build_with(entries: Vec<Entry<F>>, egress: bool, bound: u64, profile_tag: u64) -> Inst {
    let allow = vec![e(Kind::Tool, 'a'), e(Kind::Tool, 'b'), e(Kind::Tool, 'c')];
    let al: Vec<F> = allow.iter().map(allow_leaf::<H>).collect();
    let allowlist_root = tree_root::<H>(&al, ALLOWLIST_DEPTH);
    let allow_paths = entries
        .iter()
        .filter(|x| x.kind == Kind::Tool)
        .map(|x| {
            let i = allow.iter().position(|a| a.d_hi == x.d_hi && a.d_lo == x.d_lo).unwrap_or(0);
            (i as u64, tree_root_and_path::<H>(&al, i, ALLOWLIST_DEPTH).1)
        })
        .collect();
    let policy = PolicyOpening { allowlist_root, egress_allowed: egress, payment_bound: bound };
    let (nk, r) = (F::from_u64(11), F::from_u64(22));
    let tb = F::from_u64(77);
    let statement = Statement {
        profile_tag: F::from_u64(profile_tag),
        task_binding: tb,
        step_count: F::from_u64(entries.len() as u64),
        transcript: transcript::<H>(tb, &entries),
        nk_commitment: nk_commitment::<H>(nk, r),
    };
    let mut leaves: Vec<F> = (0..6).map(|i| log_leaf::<H>(F::from_u64(500 + i))).collect();
    leaves[4] = log_leaf::<H>(statement.h_s::<H>());
    let (root, log_path) = tree_root_and_path::<H>(&leaves, 4, LOG_DEPTH);
    let scope = F::from_u64(99);
    let public = Public {
        profile_tag: F::from_u64(0x0b), // the receipt names profile b
        log_root: root,
        tree_size: 6,
        policy_commitment: policy_commitment::<H>(allowlist_root, egress, bound),
        nullifier_scope: scope,
        nullifier: nullifier::<H>(nk, scope),
    };
    Inst { entries, allow, allow_paths, policy, statement, leaf_index: 4, log_path, public, nk, r }
}

fn build(entries: Vec<Entry<F>>, egress: bool, bound: u64) -> Inst {
    build_with(entries, egress, bound, 0x0b)
}

fn holds(i: &Inst) -> bool {
    relation_holds::<H>(
        &i.public,
        &Witness {
            statement: i.statement,
            entries: &i.entries,
            allow_paths: &i.allow_paths,
            policy: i.policy,
            leaf_index: i.leaf_index,
            log_path: &i.log_path,
            nk: i.nk,
            r: i.r,
        },
    )
}

fn run() -> Vec<Entry<F>> {
    vec![e(Kind::Tool, 'a'), e(Kind::Payment, '1'), e(Kind::Tool, 'b'), e(Kind::File, '2')]
}

#[test]
fn baseline() {
    assert!(holds(&build(run(), false, 1)));
}

/// Spec §4 and §9.1: the statement's profile_tag must equal the tag of the
/// receipt's profile. The receipt here names profile b, so only 0x0b may pass.
#[test]
fn profile_tag_is_constrained() {
    let mut accepted = vec![];
    for tag in [0x0a, 0x0b, 0x00, 0x0c, 0xff, u64::MAX] {
        if holds(&build_with(run(), false, 1, tag)) {
            accepted.push(tag);
        }
    }
    eprintln!("profile_tag values accepted by relation_holds: {accepted:x?}");
    assert_eq!(accepted, vec![0x0b], "GOT THROUGH: profile_tag values {accepted:x?} accepted");
}

#[test]
fn tool_path_reused_for_another_tool() {
    let mut i = build(run(), false, 1);
    i.allow_paths[1] = i.allow_paths[0].clone(); // path for 'a' offered for 'b'
    assert!(!holds(&i), "GOT THROUGH");
    let mut i = build(run(), false, 1);
    i.allow_paths.swap(0, 1);
    assert!(!holds(&i), "GOT THROUGH: swapped paths");
}

#[test]
fn extra_and_missing_paths() {
    let mut i = build(run(), false, 1);
    let extra = i.allow_paths[0].clone();
    i.allow_paths.push(extra);
    assert!(!holds(&i), "GOT THROUGH: extra path");
    let mut i = build(run(), false, 1);
    i.allow_paths.pop();
    assert!(!holds(&i), "GOT THROUGH: missing path");
    let mut i = build(run(), false, 1);
    i.allow_paths.clear();
    assert!(!holds(&i));
}

#[test]
fn egress_smuggled_as_other_kind() {
    // The issuer declared egress; the prover relabels it as a file. The transcript the
    // issuer signed no longer matches.
    let mut entries = run();
    entries.push(e(Kind::Egress, '3'));
    let mut i = build(entries, false, 1);
    assert!(!holds(&i));
    i.entries[4].kind = Kind::File;
    assert!(!holds(&i), "GOT THROUGH: egress relabelled as file");
    i.entries[4].kind = Kind::Payment;
    i.policy.payment_bound = 2;
    assert!(!holds(&i), "GOT THROUGH: egress relabelled as payment");
    // Relabel as tool with an allowlisted digest
    let mut entries = run();
    entries.push(e(Kind::Egress, 'c'));
    let mut i = build(entries, false, 1);
    i.entries[4].kind = Kind::Tool;
    let al: Vec<F> = i.allow.iter().map(allow_leaf::<H>).collect();
    i.allow_paths.push((2, tree_root_and_path::<H>(&al, 2, ALLOWLIST_DEPTH).1));
    assert!(!holds(&i), "GOT THROUGH: egress relabelled as tool");
}

#[test]
fn payment_counting() {
    let mut entries = run();
    for _ in 0..3 {
        entries.push(e(Kind::Payment, '9'));
    }
    assert!(holds(&build(entries.clone(), false, 4)));
    assert!(!holds(&build(entries.clone(), false, 3)), "GOT THROUGH: 4 payments under bound 3");
    assert!(!holds(&build(entries.clone(), false, 1u64 << 32)), "GOT THROUGH: bound 2^32");
    assert!(holds(&build(entries, false, (1u64 << 32) - 1)));
    // Dropping a payment from the witness breaks the transcript.
    let mut entries = run();
    entries.push(e(Kind::Payment, '9'));
    let mut i = build(entries, false, 2);
    i.entries.retain(|x| x.kind != Kind::Payment || x.d_hi != e(Kind::Payment, '9').d_hi);
    i.policy.payment_bound = 1;
    assert!(!holds(&i));
}

#[test]
fn step_count_mismatch() {
    for delta in [1i64, -1, 1 << 32] {
        let mut i = build(run(), false, 1);
        let t = i.entries.len() as i64 + delta;
        i.statement.step_count = F::from_u64(t as u64);
        // re-log the changed statement so only the step_count check can stop it
        let mut leaves: Vec<F> = (0..6).map(|k| log_leaf::<H>(F::from_u64(500 + k))).collect();
        leaves[4] = log_leaf::<H>(i.statement.h_s::<H>());
        let (root, path) = tree_root_and_path::<H>(&leaves, 4, LOG_DEPTH);
        i.public.log_root = root;
        i.log_path = path;
        assert!(!holds(&i), "GOT THROUGH: step_count off by {delta}");
    }
}

#[test]
fn leaf_index_and_tree_size_edges() {
    let mut i = build(run(), false, 1);
    i.leaf_index = 4 + (1 << 32);
    i.public.tree_size = MAX_TREE_SIZE;
    assert!(!holds(&i), "GOT THROUGH: leaf_index alias");
    let mut i = build(run(), false, 1);
    i.public.tree_size = 0;
    assert!(!holds(&i));
    let mut i = build(run(), false, 1);
    i.public.tree_size = MAX_TREE_SIZE + 1;
    assert!(!holds(&i));
    let mut i = build(run(), false, 1);
    i.public.tree_size = 4; // leaf at 4
    assert!(!holds(&i));
    // tree_size larger than the real log is accepted by the relation (head signature binds it)
    let mut i = build(run(), false, 1);
    i.public.tree_size = 1000;
    eprintln!("tree_size 1000 on a 6-leaf root: relation holds = {}", holds(&i));
}

#[test]
fn nk_and_scope_games() {
    let mut i = build(run(), false, 1);
    std::mem::swap(&mut i.nk, &mut i.r);
    assert!(!holds(&i), "GOT THROUGH: nk/r swapped");
    let mut i = build(run(), false, 1);
    i.public.nullifier = nullifier::<H>(i.r, i.public.nullifier_scope);
    assert!(!holds(&i), "GOT THROUGH: nullifier keyed by r");
    let mut i = build(run(), false, 1);
    i.public.nullifier_scope = F::from_u64(100);
    assert!(!holds(&i));
}

#[test]
fn policy_opening_games() {
    // egress flag flipped without changing the commitment
    let mut entries = run();
    entries.push(e(Kind::Egress, '3'));
    let mut i = build(entries, false, 1);
    i.policy.egress_allowed = true;
    assert!(!holds(&i), "GOT THROUGH: egress flag flipped");
    // different allowlist root
    let mut i = build(run(), false, 1);
    i.policy.allowlist_root = F::from_u64(1);
    assert!(!holds(&i));
}

#[test]
fn empty_run_and_only_files() {
    assert!(!holds(&build(vec![], false, 0)));
    assert!(holds(&build(vec![e(Kind::File, '5')], false, 0)));
}
