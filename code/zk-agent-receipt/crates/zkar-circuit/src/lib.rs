//! zkar-circuit — an off-circuit mirror of the SAR-ZK v0.4 relation.
//!
//! The relation is small on purpose so it can be audited. This crate states
//! it once, in plain Rust, over an abstract field and hash: the transcript
//! (spec §5), the policy (§6), log membership (§7.2), the nullifier-key
//! commitment and the scoped nullifier (§8). Concrete profile-b R1CS circuits
//! and the Nova prover live in the separate `zkar-prover` crate.
//!
//! Not mirrored here: the issuer signature (§3.4), which needs curve
//! arithmetic, and the folding state machine (§9.1).

use zkar_core::lexical::is_digest;

/// A field element. The real type is the Pallas base field; tests use a
/// stand-in.
pub trait FieldElement: Copy + Eq + std::fmt::Debug {
    fn from_u64(x: u64) -> Self;
    /// A 128-bit big-endian limb (spec §3.3).
    fn from_be_bytes16(b: &[u8; 16]) -> Self;
}

/// `H_D(x_1..x_k)` from spec §3.2: Poseidon with a domain tag and the input
/// length absorbed first.
pub trait FieldHasher {
    type F: FieldElement;
    fn hash(domain: &'static str, input: &[Self::F]) -> Self::F;
}

/// Depth of the log tree (spec §7.2).
pub const LOG_DEPTH: usize = 32;
/// Depth of the allowlist tree (spec §6).
pub const ALLOWLIST_DEPTH: usize = 16;
/// Largest tree size the log allows (spec §7.1).
pub const MAX_TREE_SIZE: u64 = 2_147_483_647;

/// Entry kinds (spec §5.1). Padding (kind 0) exists only inside the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tool = 1,
    Egress = 2,
    File = 3,
    Payment = 4,
}

/// One inventory entry: a kind and a SHA-256 digest as two 128-bit limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<F> {
    pub kind: Kind,
    pub d_hi: F,
    pub d_lo: F,
}

impl<F: FieldElement> Entry<F> {
    /// Build an entry from a v0.2 `DIGEST` string. Returns None if the digest
    /// is not in `sha256:` + 64 lowercase hex form.
    pub fn from_digest(kind: Kind, digest: &str) -> Option<Self> {
        let (hi, lo) = digest_limbs(digest)?;
        Some(Entry { kind, d_hi: F::from_be_bytes16(&hi), d_lo: F::from_be_bytes16(&lo) })
    }
}

/// Split a v0.2 digest into its two 16-byte big-endian halves.
pub fn digest_limbs(digest: &str) -> Option<([u8; 16], [u8; 16])> {
    if !is_digest(digest) {
        return None;
    }
    let hex = &digest.as_bytes()[7..];
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&out[..16]);
    lo.copy_from_slice(&out[16..]);
    Some((hi, lo))
}

/// The fixed-size statement S (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statement<F> {
    pub profile_tag: F,
    pub task_binding: F,
    pub step_count: F,
    pub transcript: F,
    pub nk_commitment: F,
}

impl<F: FieldElement> Statement<F> {
    /// `h_S`, the value profile b signs and the log leaf hashes.
    pub fn h_s<H: FieldHasher<F = F>>(&self) -> F {
        H::hash(
            "SAR-ZK statement",
            &[self.profile_tag, self.task_binding, self.step_count, self.transcript, self.nk_commitment],
        )
    }
}

/// The transcript t_T (spec §5.2).
pub fn transcript<H: FieldHasher>(task_binding: H::F, entries: &[Entry<H::F>]) -> H::F {
    let mut t = H::hash("SAR-ZK transcript", &[task_binding]);
    for (i, e) in entries.iter().enumerate() {
        let pos = H::F::from_u64(i as u64 + 1);
        t = H::hash("SAR-ZK step", &[t, pos, H::F::from_u64(e.kind as u64), e.d_hi, e.d_lo]);
    }
    t
}

/// The nullifier-key commitment `H_nk(nk, r)` (spec §8.1).
pub fn nk_commitment<H: FieldHasher>(nk: H::F, r: H::F) -> H::F {
    H::hash("SAR-ZK nk", &[nk, r])
}

/// The scoped nullifier `H_nf(nk, scope)` (spec §8.2). It does not depend on
/// the log position, so logging one statement twice gives one nullifier.
pub fn nullifier<H: FieldHasher>(nk: H::F, scope: H::F) -> H::F {
    H::hash("SAR-ZK nullifier", &[nk, scope])
}

/// The policy commitment `H_policy(allowlist_root, egress_allowed, payment_bound)`.
pub fn policy_commitment<H: FieldHasher>(allowlist_root: H::F, egress_allowed: bool, payment_bound: u64) -> H::F {
    H::hash(
        "SAR-ZK policy",
        &[allowlist_root, H::F::from_u64(egress_allowed as u64), H::F::from_u64(payment_bound)],
    )
}

/// Hashes of empty subtrees: `z[0] = H_empty()`, `z[l+1] = H_node(z[l], z[l])`.
pub fn empty_subtrees<H: FieldHasher>(depth: usize) -> Vec<H::F> {
    let mut z = vec![H::hash("SAR-ZK empty", &[])];
    for l in 0..depth {
        let n = H::hash("SAR-ZK node", &[z[l], z[l]]);
        z.push(n);
    }
    z
}

/// Root of a fixed-depth tree whose first `leaves.len()` positions hold
/// `leaves` (already hashed) and every other position holds `H_empty()`.
pub fn tree_root<H: FieldHasher>(leaves: &[H::F], depth: usize) -> H::F {
    tree_root_and_path::<H>(leaves, 0, depth).0
}

/// Root and authentication path for `index`. Works for sparse trees: cost is
/// linear in the number of leaves, not in 2^depth.
///
/// Panics if there are more leaves than the tree holds, or if `index` is
/// outside the tree: silently dropping leaves would give a wrong root.
pub fn tree_root_and_path<H: FieldHasher>(leaves: &[H::F], index: usize, depth: usize) -> (H::F, Vec<H::F>) {
    let cap = 1u128 << depth;
    assert!(
        (leaves.len() as u128) <= cap && (index as u128) < cap,
        "tree of depth {depth} holds {cap} leaves; got {} leaves and index {index}",
        leaves.len()
    );
    let z = empty_subtrees::<H>(depth);
    if depth == 0 {
        return (*leaves.first().unwrap_or(&z[0]), vec![]);
    }
    let mut level: Vec<H::F> = leaves.to_vec();
    let mut idx = index;
    let mut path = Vec::with_capacity(depth);
    for l in 0..depth {
        let sib = idx ^ 1;
        path.push(*level.get(sib).unwrap_or(&z[l]));
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { z[l] };
            next.push(H::hash("SAR-ZK node", &[pair[0], right]));
        }
        if next.is_empty() {
            next.push(z[l + 1]);
        }
        level = next;
        idx >>= 1;
    }
    (level[0], path)
}

fn climb<H: FieldHasher>(mut node: H::F, path: &[H::F], index: u64) -> H::F {
    for (level, sibling) in path.iter().enumerate() {
        let (l, r) = if (index >> level) & 1 == 0 { (node, *sibling) } else { (*sibling, node) };
        node = H::hash("SAR-ZK node", &[l, r]);
    }
    node
}

/// Log membership (spec §7.2). The leaf is hashed here, under its own label,
/// so an internal node can never pass as a leaf.
pub fn log_member<H: FieldHasher>(h_s: H::F, path: &[H::F], leaf_index: u64, tree_size: u64, root: H::F) -> bool {
    path.len() == LOG_DEPTH
        && (1..=MAX_TREE_SIZE).contains(&tree_size)
        && leaf_index < tree_size
        && climb::<H>(H::hash("SAR-ZK leaf", &[h_s]), path, leaf_index) == root
}

/// The log leaf for a statement hash.
pub fn log_leaf<H: FieldHasher>(h_s: H::F) -> H::F {
    H::hash("SAR-ZK leaf", &[h_s])
}

/// Allowlist membership (spec §6). Empty positions hash under a different
/// label, so they never match an allowed digest.
pub fn allow_member<H: FieldHasher>(e: &Entry<H::F>, path: &[H::F], index: u64, root: H::F) -> bool {
    path.len() == ALLOWLIST_DEPTH
        && index < (1u64 << ALLOWLIST_DEPTH)
        && climb::<H>(allow_leaf::<H>(e), path, index) == root
}

/// The canonical allowlist root for a policy: leaves in the policy's sorted,
/// duplicate-free order (spec §6). Verifiers should compute the root this way.
pub fn allowlist_root<H: FieldHasher>(policy: &zkar_core::policy::Policy) -> H::F {
    let leaves: Vec<H::F> = policy
        .allowlist()
        .iter()
        .map(|d| allow_leaf::<H>(&Entry::from_digest(Kind::Tool, d).expect("Policy::new checked the digest")))
        .collect();
    tree_root::<H>(&leaves, ALLOWLIST_DEPTH)
}

/// The allowlist leaf for one tool digest.
pub fn allow_leaf<H: FieldHasher>(e: &Entry<H::F>) -> H::F {
    H::hash("SAR-ZK allow", &[e.d_hi, e.d_lo])
}

/// Public values the verifier fixes (spec §10), minus the signature fields.
#[derive(Debug, Clone, Copy)]
pub struct Public<F> {
    /// The tag of the receipt's profile: 0x0a for profile a, 0x0b for b.
    pub profile_tag: F,
    pub log_root: F,
    pub tree_size: u64,
    pub policy_commitment: F,
    pub nullifier_scope: F,
    pub nullifier: F,
}

/// The policy opening the prover supplies.
#[derive(Debug, Clone, Copy)]
pub struct PolicyOpening<F> {
    pub allowlist_root: F,
    pub egress_allowed: bool,
    pub payment_bound: u64,
}

/// Everything the prover knows (spec §2), minus the issuer signature.
pub struct Witness<'a, F> {
    pub statement: Statement<F>,
    pub entries: &'a [Entry<F>],
    /// For each tool entry, in order: (allowlist index, allowlist path).
    pub allow_paths: &'a [(u64, Vec<F>)],
    pub policy: PolicyOpening<F>,
    pub leaf_index: u64,
    pub log_path: &'a [F],
    pub nk: F,
    pub r: F,
}

/// The relation the three circuits prove together (spec §2 items 2–5), minus
/// the issuer signature. Returns true only if every check holds.
pub fn relation_holds<H: FieldHasher>(public: &Public<H::F>, w: &Witness<'_, H::F>) -> bool {
    let p = &w.policy;
    if p.payment_bound >= (1u64 << 32) {
        return false;
    }
    if policy_commitment::<H>(p.allowlist_root, p.egress_allowed, p.payment_bound) != public.policy_commitment {
        return false;
    }
    let mut tool_paths = w.allow_paths.iter();
    let mut payments: u64 = 0;
    for e in w.entries {
        match e.kind {
            Kind::Tool => match tool_paths.next() {
                Some((idx, path)) if allow_member::<H>(e, path, *idx, p.allowlist_root) => {}
                _ => return false,
            },
            Kind::Egress if !p.egress_allowed => return false,
            Kind::Payment => payments += 1,
            _ => {}
        }
    }
    if tool_paths.next().is_some() || payments > p.payment_bound {
        return false;
    }
    let s = &w.statement;
    if s.profile_tag != public.profile_tag {
        return false;
    }
    let t = w.entries.len() as u64;
    if t == 0 || t >= (1u64 << 32) || s.step_count != H::F::from_u64(t) {
        return false;
    }
    if transcript::<H>(s.task_binding, w.entries) != s.transcript {
        return false;
    }
    if nk_commitment::<H>(w.nk, w.r) != s.nk_commitment {
        return false;
    }
    if !log_member::<H>(s.h_s::<H>(), w.log_path, w.leaf_index, public.tree_size, public.log_root) {
        return false;
    }
    nullifier::<H>(w.nk, public.nullifier_scope) == public.nullifier
}

/// A test stand-in for a field element. It is NOT a field and NOT range
/// checked; it exists so the relation's logic can be tested without Poseidon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceholderField(pub u64);

impl FieldElement for PlaceholderField {
    fn from_u64(x: u64) -> Self {
        PlaceholderField(x)
    }
    fn from_be_bytes16(b: &[u8; 16]) -> Self {
        PlaceholderField(b.iter().fold(0xcbf29ce484222325u64, |a, &x| (a ^ x as u64).wrapping_mul(0x100000001b3)))
    }
}

/// A test stand-in for Poseidon: order-sensitive and domain-separated, so the
/// tests can catch a missing label. It is NOT collision resistant.
pub struct TestHasher;

impl FieldHasher for TestHasher {
    type F = PlaceholderField;
    fn hash(domain: &'static str, input: &[PlaceholderField]) -> PlaceholderField {
        let mut a = 0xcbf29ce484222325u64;
        for &b in domain.as_bytes() {
            a = (a ^ b as u64).wrapping_mul(0x100000001b3);
        }
        a = (a ^ input.len() as u64).wrapping_mul(0x100000001b3);
        for x in input {
            a = (a ^ x.0).wrapping_mul(0x100000001b3).rotate_left(29);
        }
        PlaceholderField(a)
    }
}
