//! attack2: tree_root_and_path against a naive full-tree builder, every index,
//! every leaf count, depths 0..=7. Convention: assertions state the defence.

use zkar_circuit::*;

type F = PlaceholderField;
type H = TestHasher;

/// Naive: materialise all 2^depth leaves, pad with H_empty(), hash level by level.
fn naive(leaves: &[F], index: usize, depth: usize) -> (F, Vec<F>) {
    let e = H::hash("SAR-ZK empty", &[]);
    let n = 1usize << depth;
    assert!(leaves.len() <= n);
    let mut level: Vec<F> = (0..n).map(|i| *leaves.get(i).unwrap_or(&e)).collect();
    let mut idx = index;
    let mut path = vec![];
    for _ in 0..depth {
        path.push(level[idx ^ 1]);
        level = level.chunks(2).map(|p| H::hash("SAR-ZK node", &[p[0], p[1]])).collect();
        idx >>= 1;
    }
    (level[0], path)
}

fn leaves(n: usize) -> Vec<F> {
    (0..n).map(|i| log_leaf::<H>(F::from_u64(0x1000 + i as u64))).collect()
}

fn climb(mut node: F, path: &[F], index: u64) -> F {
    for (l, s) in path.iter().enumerate() {
        node = if (index >> l) & 1 == 0 { H::hash("SAR-ZK node", &[node, *s]) } else { H::hash("SAR-ZK node", &[*s, node]) };
    }
    node
}

#[test]
fn matches_naive_for_every_count_and_index() {
    let mut checked = 0;
    for depth in 1..=7usize {
        let cap = 1usize << depth;
        for n in 0..=cap {
            let ls = leaves(n);
            for index in 0..cap {
                let got = tree_root_and_path::<H>(&ls, index, depth);
                let want = naive(&ls, index, depth);
                assert_eq!(got, want, "depth {depth} n {n} index {index}");
                // path must climb back to the root from the leaf (or the empty value)
                let leaf = *ls.get(index).unwrap_or(&H::hash("SAR-ZK empty", &[]));
                assert_eq!(climb(leaf, &got.1, index as u64), got.0);
                checked += 1;
            }
        }
    }
    eprintln!("checked {checked} (depth, count, index) triples");
}

#[test]
fn empty_tree_root_is_top_empty_subtree() {
    for d in 1..=LOG_DEPTH {
        assert_eq!(tree_root::<H>(&[], d), empty_subtrees::<H>(d)[d]);
    }
    assert_eq!(tree_root::<H>(&[], LOG_DEPTH), naive_empty_top(LOG_DEPTH));
}

fn naive_empty_top(d: usize) -> F {
    let mut z = H::hash("SAR-ZK empty", &[]);
    for _ in 0..d {
        z = H::hash("SAR-ZK node", &[z, z]);
    }
    z
}

/// depth 0 with no leaves: the root should be H_empty(); the function panics instead.
#[test]
fn depth_zero_empty_tree() {
    let r = std::panic::catch_unwind(|| tree_root_and_path::<H>(&[], 0, 0));
    eprintln!("depth 0, no leaves: panicked = {}", r.is_err());
    assert!(r.is_ok(), "GOT THROUGH: tree_root_and_path(&[], 0, 0) panics");
}

/// More leaves than the tree holds: the function must refuse, not silently drop leaves.
#[test]
fn over_capacity_is_refused_not_truncated() {
    let ls = leaves(9); // capacity of a depth-3 tree is 8
    let r = std::panic::catch_unwind(|| tree_root_and_path::<H>(&ls, 0, 3));
    assert!(r.is_err(), "GOT THROUGH: a 9th leaf was silently dropped from the root");
}

/// Index past capacity must be refused, not answered with a path for index & 7.
#[test]
fn index_past_capacity_is_refused() {
    let ls = leaves(3);
    let r = std::panic::catch_unwind(|| tree_root_and_path::<H>(&ls, 8 + 1, 3));
    assert!(r.is_err(), "GOT THROUGH: index 9 in a depth-3 tree returned a path");
}

/// log_member: leaf_index aliasing near 2^32 and tree_size bounds.
#[test]
fn log_member_index_aliasing_and_bounds() {
    let ls = leaves(5);
    let h = F::from_u64(0x1003);
    let (root, path) = tree_root_and_path::<H>(&ls, 3, LOG_DEPTH);
    assert!(log_member::<H>(h, &path, 3, 5, root));
    // 3 + 2^32 has the same low 32 bits: the climb is identical.
    let alias = 3u64 + (1 << 32);
    assert!(!log_member::<H>(h, &path, alias, MAX_TREE_SIZE, root), "GOT THROUGH: index alias 3+2^32");
    assert!(!log_member::<H>(h, &path, u64::MAX, MAX_TREE_SIZE, root));
    assert!(!log_member::<H>(h, &path, 3, 0, root));
    assert!(!log_member::<H>(h, &path, 3, MAX_TREE_SIZE + 1, root));
    assert!(!log_member::<H>(h, &path, 3, u64::MAX, root));
    assert!(!log_member::<H>(h, &path, 5, 5, root));
    // a 33-element path
    let mut long = path.clone();
    long.push(F::from_u64(0));
    assert!(!log_member::<H>(h, &long, 3, 5, root));
    // an empty slot (index 7 < tree_size 8 but leaf there is H_empty) cannot be claimed by any h_s
    // unless H_leaf(h_s) == H_empty(): we only check the honest path does not accidentally match.
    let (root8, p7) = tree_root_and_path::<H>(&ls, 7, LOG_DEPTH);
    assert!(!log_member::<H>(h, &p7, 7, 8, root8));
}

/// allow_member: index aliasing past 2^16 and path-length games.
#[test]
fn allow_member_bounds() {
    let tools: Vec<Entry<F>> = (0..3u8)
        .map(|i| Entry::from_digest(Kind::Tool, &format!("sha256:{}", format!("{:02x}", i + 0xa0).repeat(32))).unwrap())
        .collect();
    let al: Vec<F> = tools.iter().map(allow_leaf::<H>).collect();
    let (root, path) = tree_root_and_path::<H>(&al, 2, ALLOWLIST_DEPTH);
    assert!(allow_member::<H>(&tools[2], &path, 2, root));
    assert!(!allow_member::<H>(&tools[2], &path, 2 + (1 << 16), root), "GOT THROUGH: allowlist index alias");
    assert!(!allow_member::<H>(&tools[1], &path, 2, root));
    assert!(!allow_member::<H>(&tools[2], &path[..15], 2, root));
    // an empty slot: E itself is not an allow leaf
    let (_, p5) = tree_root_and_path::<H>(&al, 5, ALLOWLIST_DEPTH);
    assert!(!allow_member::<H>(&tools[0], &p5, 5, root));
    // A Kind::Egress entry with an allowed digest still produces the same allow leaf:
    // the leaf does not bind the kind. relation_holds only asks for paths on Kind::Tool,
    // so this is not exploitable there; recorded for the circuit authors.
    let as_egress = Entry { kind: Kind::Egress, ..tools[2] };
    assert!(allow_member::<H>(&as_egress, &path, 2, root));
}
