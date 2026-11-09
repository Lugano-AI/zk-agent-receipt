# Sealed Agent Receipt Profile SAR-ZK v0.4-draft

**Status:** draft for public comment. Not externally audited. An unaudited
native reference implementation of profile b exists (§9.1, "uniform
instantiation"). Normative language follows
RFC 2119 and RFC 8174. This profile builds on Signed Agent Receipt Reference
Profile v0.2 (`sar-ri-*`) but defines a new statement format and a new log.

This profile lets a **holder** prove to a **verifier** that a task record
satisfies a policy the verifier chooses, without showing the record. It does
not verify execution, observation, retention, time or hardware. The v0.2
scope markers (v0.2 §1) apply unchanged.

## 1. Roles

- **Issuer.** Signs one statement per agent task. The issuer is trusted for the
  content it declares. A realistic issuer is a party that sits between the agent
  and its tools, such as a tool gateway run by a separate provider. The issuer
  does not take part in proving.
- **Log signer.** Appends statement leaves to a SAR-ZK log and signs tree heads.
- **Holder.** Generates the per-receipt nullifier key `nk`, keeps the task's
  inventory entries, and produces sealed receipts.
- **Verifier.** Pins issuer and log keys out of band (v0.2 §2 rules, including
  issuer/log key separation), chooses the policy and the nullifier scope, and
  checks sealed receipts. "Verifier" and "relying party" mean the same role.

## 2. What a pass establishes

Given a sealed receipt, a pinned issuer key, a pinned log key, an expected
policy commitment and an expected scope, a pass establishes only that the
prover knew:

1. a statement `S` (§4) whose issuer signature verifies under a key whose
   commitment equals `issuer_key_commitment`;
2. a sequence of `S.step_count` inventory entries whose transcript (§5.2)
   equals `S.transcript`;
3. that every entry satisfies the policy committed in `policy_commitment`
   (§6), and the payment count is at most the committed bound;
4. that `leaf(S)` sits at an index below `tree_size` in the tree whose root is
   `log_root`, and the log head carries a valid signature under the pinned log
   key (§7);
5. an opening `(nk, r)` of `S.nk_commitment`, and that
   `nullifier = H_nf(nk, nullifier_scope)` (§8).

A pass does **not** establish freshness, issuer honesty, inventory
completeness, that the holder presented every receipt (outside audit mode,
§8.3), artifact reality, agent execution, or that any v0.2 log contains
the record. The only passing result string is `SEALED CHECK PASSED`, and only
an implementation that verifies the proof (§9 step 3) may print it.
Implementations MUST NOT print `VERIFIED`.

## 3. Primitives

### 3.1 Fields and curves
All circuit values are elements of the Pallas base field `F_p`, with
`p = 28948022309329048855892746252171976963363056481941560715954676764349967630337`.
Recursion uses the Pallas/Vesta cycle. On the wire, a field element is a
`DECIMAL` (v0.2 §3.1) whose value is less than `p`. Implementations MUST reject
any value `>= p`; they MUST NOT reduce it.

### 3.2 Poseidon
`Poseidon` is the permutation used by Zcash Orchard (`P128Pow5T3`): width 3,
rate 2, S-box `x^5`, 8 full rounds, 56 partial rounds, over `F_p`.

For a domain label `D` (ASCII, at most 31 bytes) and inputs `x_1..x_k`:

```text
H_D(x_1..x_k) = Sponge(tag(D), k, x_1, ..., x_k)
```

`tag(D)` is the big-endian integer of `D`'s bytes. `Sponge` keeps a state
`(s_0, s_1, s_2)`: `s_0` and `s_1` are the rate, `s_2` is the capacity, and all
three start at zero. Its input list is `tag(D), k, x_1, ..., x_k`, so
`(tag(D), k)` is always the first pair absorbed. It takes the list two at a
time (zero-padding the last pair), adds them to `s_0` and `s_1` in the field, and applies the permutation
after each pair. The output is `s_0` after the last permutation. Absorbing `k`
removes any ambiguity between inputs of different lengths; collision
resistance itself remains a computational assumption.

Domain labels used in this profile: `SAR-ZK statement`, `SAR-ZK leaf`,
`SAR-ZK node`, `SAR-ZK empty`, `SAR-ZK transcript`, `SAR-ZK step`,
`SAR-ZK allow`, `SAR-ZK policy`, `SAR-ZK nk`, `SAR-ZK nullifier`,
`SAR-ZK scope`, `SAR-ZK acc`, `SAR-ZK issuer`, `SAR-ZK schnorr`. Test vectors are pending; until they exist,
two implementations cannot claim compatibility.

### 3.3 Digests
An inventory digest is a v0.2 `DIGEST` (SHA-256). In the circuit it is two
128-bit limbs, `(d_hi, d_lo)`, taken big-endian from the 32 digest bytes.

### 3.4 Signatures
- **Profile `sar-zk-v0.4b` (first target).** Schnorr over Pallas
  (`y^2 = x^3 + 5` over `F_p`), with generator `G = (p - 1, 2)` and scalar
  order `q`. The issuer's secret key `sk` is uniform in `[1, q-1]`, and its
  public key is `PK = sk·G`. To sign a field element `m`, the issuer picks a
  uniformly random nonce `k` in `[1, q-1]`, never reused, and sets `R = k·G`,
  `c = H_schnorr(R.x, R.y, PK.x, PK.y, m)` and `s = k + c·sk mod q`. Because
  `p < q`, `c` is a valid scalar without reduction. The signature is `(R, s)`.
  A verifier, in or out of the circuit, MUST check that `PK` and `R` are on the
  curve and are not the identity, and that `s < q`. In the circuit, `s` and `c`
  are decomposed into 255 bits with a canonical range check, and the equation
  uses complete addition formulas. Verification checks `s·G = R + c·PK`.
  `issuer_key_commitment = H_issuer(PK.x, PK.y)`.
- **Profile `sar-zk-v0.4a`.** Ed25519 (RFC 8032, pure) over `enc(S)` (§4),
  verified in the circuit with non-native arithmetic and SHA-512.
  Verification is cofactorless, rejects non-canonical `s`, and rejects
  small-order `A` and `R`. `issuer_key_commitment = H_issuer(A_hi, A_lo)` over
  the 32-byte public key split into two 128-bit limbs.

The two profiles are distinct trust statements. A receipt MUST name its profile.
The log head signature (§7) is always Ed25519 checked outside the circuit, with
the same verification rule as profile a. Every Ed25519 key, issuer or log, MUST
be canonically encoded and lie in the prime-order subgroup; keys with a
small-order component are rejected, so cofactored and cofactorless verifiers
cannot disagree about a signature.

## 4. The statement S

`S` has a fixed size. It never contains the inventory itself.

```text
S = {
  profile_tag:   F,   // 0x0a for profile a, 0x0b for profile b
  task_binding:  F,   // issuer's commitment to the task's metadata
  step_count:    F,   // T, the number of inventory entries; 1 <= T < 2^32
  transcript:    F,   // t_T from §5.2
  nk_commitment: F    // H_nk(nk, r) from §8.1
}
h_S     = H_statement(profile_tag, task_binding, step_count, transcript, nk_commitment)
leaf(S) = H_leaf(h_S)
enc(S)  = ASCII("SAR-ZK-statement-v0.4") || 0x00 || 32-byte big-endian encoding of each field, in order
```

Profile b signs `h_S`. Profile a signs `enc(S)`. Both encodings are fixed-length
and injective. Because `S` has a fixed size, the signature cost does not grow
with the length of the run.

## 5. Inventory entries and the transcript

### 5.1 Entries
The task's inventory is a sequence of entries `e_1..e_T`. Each entry is
`(kind, d_hi, d_lo)` with `kind` in {1 = tool, 2 = egress, 3 = file,
4 = payment}. Kind 0 is a padding step. It exists only inside the proof
(§9.1) and never enters the transcript. An entry declares that the issuer saw the artifact; it is not an
observation the proof can check.

### 5.2 Transcript
```text
t_0 = H_transcript(task_binding)
t_i = H_step(t_{i-1}, i, kind_i, d_hi_i, d_lo_i)      for i = 1..T
```
The issuer computes `t_T` from the entries it declares and signs it inside `S`.
The holder keeps the entries. Any change to an entry, its order or its count
changes `t_T`.

## 6. Policy

A policy is `(allowlist_root, egress_allowed, payment_bound)`:

- `allowlist_root` is the root of a depth-16 Merkle tree (§7.2 rules, with
  `H_allow(d_hi, d_lo)` leaves) over the sorted, duplicate-free list of allowed
  tool digests. Lists longer than 65,536 entries are out of scope.
- `egress_allowed` is 0 or 1.
- `payment_bound` is an integer below `2^32`.

`policy_commitment = H_policy(allowlist_root, egress_allowed, payment_bound)`.
The verifier MUST compute or pin the expected commitment and reject a
mismatch. An entry satisfies the policy when:

1. a tool entry's digest is in the allowlist (a membership path is a witness);
2. an egress entry appears only if `egress_allowed = 1`;
3. file entries are unconstrained.

The run satisfies the policy when every entry does and the number of payment
entries is at most `payment_bound`. Counts, not amounts: an entry encodes a
payment event, not a value. An empty egress list is an issuer-declared absence
of egress, not an observed one. Other policy shapes are out of scope.

## 7. The SAR-ZK log

### 7.1 Signed head
The log head is `(profile, hash_suite, log_id, log_root, tree_size)`, with
`hash_suite = "poseidon-pallas-p128pow5t3"`. The log signer signs:

```text
headBytes = ASCII("SAR-ZK-head-v0.4") || 0x00
            || frame(profile) || frame(hash_suite) || frame(log_id)
            || frame(log_root) || frame(tree_size)
frame(x)  = 2-byte big-endian length of x || x        (x as its ASCII wire form)
```

`tree_size` is a `DECIMAL` in `1..2147483647`. `log_root` is a field element.

### 7.2 Tree
The tree has fixed depth 32. Leaf `i` is `leaf(S_i)` for `i < tree_size`. Every
position at or above `tree_size` holds `E = H_empty()`. Internal nodes are
`H_node(left, right)`. This is a fixed-depth tree, not the RFC 9162 shape. Leaf,
node and empty values use distinct domain labels, so no internal node can pass
as a leaf. A v0.2 SHA-256 inclusion proof does not transfer, and a v0.2
statement cannot be converted: SAR-ZK records require fresh issuance.

### 7.3 Log duties
The log signer SHOULD reject duplicate leaves, and MUST reject them in an
account log (§8.3). A production deployment MUST gossip signed heads in the
manner of Certificate Transparency (RFC 9162). A deployment that does not is a
test deployment and MUST say so. A log signer that signs tiny trees can shrink
the candidate set (§11) to one record.

A verifier MAY accept heads from any log in a pinned set. A holder or issuer
MAY then submit a leaf to any log in that set, so a single log signer cannot
block a receipt by refusing to append it.

## 8. Issuance and the nullifier

### 8.1 Issuance
1. The holder samples a fresh `nk` uniformly from `F_p` for this receipt, and
   `r` uniformly from `F_p`. A holder MUST NOT reuse `nk` across receipts:
   with a shared `nk`, every receipt gives the same nullifier in a scope, and
   the nullifier becomes a pseudonym for the holder.
   It computes `nk_commitment = H_nk(nk, r)` and sends only `nk_commitment` to
   the issuer.
2. The issuer computes `transcript` from the entries it declares, builds `S`,
   signs it, and returns `S`, the signature and the entries to the holder.
3. The issuer or the holder submits `leaf(S)` to the log. The log signer
   appends it and later signs a head that covers it.
4. The holder obtains the membership path from the log. A path request names
   a leaf, so the log learns which receipt the requester holds, and a log that
   colludes with a verifier can match the request to a later presentation.
   Holders SHOULD fetch paths at issuance or in batches that cover many
   receipts, refresh them on a schedule that does not depend on presentations,
   and never fetch a path just before presenting. Deployments that need more
   SHOULD serve paths by private information retrieval or download of whole
   tree levels, over an anonymous transport.

The issuer never sees `nk` or `r`. Each receipt MUST use an independent fresh
pair `(nk, r)` from a CSPRNG. What reuse or leakage costs:

| Event | Consequence |
|---|---|
| `nk` reused, fresh `r` | The receipts give the same nullifier in every scope; the nullifier becomes a holder pseudonym. |
| `nk` and `r` reused | The receipts also share `nk_commitment`, so the issuer and the log can link them in any scope. |
| `nk` leaks | Anyone can compute the receipt's nullifier for any scope and link its presentations across scopes. |
| `nk` and `r` leak | A thief can prove the receipt and plant its nullifier in replay sets first. Treat as compromise: the holder MUST stop presenting the receipt and SHOULD ask the issuer to reissue. |
| `rho` reused | Recursive proofs with the same entries carry the same states. Compressed proofs do not show them, but `rho` MUST be fresh for every presentation (§9.1). |

Leaf hiding (§11) protects a record against guessing. It does not protect a
record whose `S` later becomes known: anyone who learns `S` can compute
`leaf(S)` without `nk` or `r`. An issuer MUST NOT sign two statements for
the same task. Nothing in this profile can detect a breach of that rule.

### 8.2 Nullifier
```text
nullifier = H_nf(nk, nullifier_scope)
```
The verifier chooses `nullifier_scope`. A RECOMMENDED form is
`H_scope(verifier_id, purpose)`, where both inputs are field elements the
deployment defines; any public field element is valid. The same receipt proven twice under the same
scope gives the same nullifier, so a verifier that keeps a nullifier set sees
the repeat. The nullifier does not depend on the log position, so logging the
same `S` twice does not create a second nullifier. Under honestly distinct scopes, nullifier
values cannot be linked while `nk` stays secret, assuming `H_nf` keyed by `nk`
behaves as a PRF. That covers nullifier values only. Whole presentations can
still be linked through a shared scope, the rest of the public input, a small
candidate set (§11), timing, or colluding verifiers. Colluding verifiers can
always agree to share a scope.

A verifier that wants no replay detection uses a fresh random scope for each
presentation. Verifiers that share one scope share replay detection, and they
also learn when the same receipt was shown to both. A deployment MUST state
which verifiers share a scope.

### 8.3 Audit mode: completeness over a period
Outside this mode, the holder chooses which receipts to present, so a verifier
learns only that the presented records comply. Audit mode lets a verifier
check every receipt of one account in one period, with no circuit change.

1. The issuer MUST append the leaf of every receipt it issues for the audited
   account to one **account log**, within a deadline the deployment states. The
   account log holds only that account's leaves. The holder MUST NOT run it.
2. The account log's signer MUST reject duplicate leaves.
3. The verifier fixes one signed head `(log_root, n)` of the account log for
   the period end, one audit policy, and one fresh scope for the audit.
4. The holder presents `n` sealed receipts against that `log_root`, policy and
   scope.
5. The verifier accepts the audit only if all `n` verify and their nullifiers
   are pairwise distinct.

Why this works: each `S` carries one `nk_commitment`, and Poseidon is
collision resistant, so each logged `S` gives at most one nullifier per scope.
So `n` distinct nullifiers under a root with `n` positions cover every
position. A record that breaks the policy cannot be proven, so the holder
cannot reach `n`. A missing proof means a withheld or failing record. A
reissued receipt is an extra leaf that the holder must also prove.

What it costs: the verifier learns `n`, and the candidate set is the account's
own records. Audit mode hides what the records say, not whose they are. It
still trusts the issuer to log every receipt it issues.

## 9. Proof system and verification

### 9.1 Construction
The proof is a non-uniform IVC proof in the SuperNova style over the
Pallas/Vesta cycle. In IVC the initial and final states are public, so the
running values must not appear in them in the clear. The state is

```text
z   = (pc, acc, public_bind, out)
acc = H_acc(t, i, pay_count, allowlist_root, egress_allowed, payment_bound, rho)
```

`H_acc` is `H_D` from §3.2 with the label `SAR-ZK acc`. Every circuit that
reads `acc` takes its seven inputs as witnesses and recomputes it, so a
transition can only start from a state the previous circuit produced (by
collision resistance). That `acc` hides the running values is an assumption:
fixed-length Poseidon with a uniform `rho` is treated as a hiding commitment.

`public_bind` holds `profile_tag` (the tag of the receipt's `profile`),
`issuer_key_commitment`, `log_root`, `tree_size`, `policy_commitment` and
`nullifier_scope`. No circuit may change it. `rho` is a
fresh random value the prover picks for each proof, so `acc` hides the running
values. There are three step circuits, selected by `pc`:

- `F_start` (needs `pc = START`, runs once, first). It takes the policy and `rho`
  as witnesses, checks `H_policy(allowlist_root, egress_allowed, payment_bound)
  = policy_commitment`, and sets `acc` with `t = H_transcript(task_binding)`,
  `i = 0`, `pay_count = 0`. It sets `pc = STEP`.
- `F_step` (needs `pc = STEP`). It opens `acc` and branches on `kind`:
  - For `kind` in 1..4 (one step per real entry), it checks the entry against
    the policy (§6), sets `t' = H_step(t, i+1, kind, d_hi, d_lo)` and
    `i' = i + 1`, and adds 1 to `pay_count` for a payment entry.
  - For `kind = 0` (padding), it leaves `t`, `i` and `pay_count` unchanged.
  - Any other `kind` makes `F_step` unsatisfiable.

  Either way it writes `acc` again from the resulting values and the same
  `rho`. So `i` always counts real entries, not folds. Padding hides the run
  length up to a bucket (§11).
- `F_final` (needs `pc = STEP`, runs once, last). It opens `acc` and checks
  `S.profile_tag` equals the `profile_tag` in `public_bind`,
  `S.transcript = t`, `S.step_count = i` (with `S.step_count` range-checked to
  `1 <= T < 2^32`), `pay_count <= payment_bound` (with 32-bit range checks on
  both), the issuer signature, membership of `leaf(S)`
  (with `leaf_index` constrained to 32 bits and checked to be below
  `tree_size`), the opening of `nk_commitment`, and the nullifier. The issuer computed
  `S.transcript` starting from `S.task_binding`, so the transcript equality
  also binds the `task_binding` that `F_start` used (by collision resistance).
  It sets `pc = HALT`, `acc = 0` and `out = nullifier`.

The verifier sets the initial state to `(START, 0, public_bind, 0)` from its own
expected values, and checks that the output state is
`(HALT, 0, public_bind, nullifier)`. Without the `pc = HALT` check, a proof that
never ran `F_final` would pass. Each fold pays only for the circuit it runs, so
the signature cost is paid once per proof, not once per step.

An implementation MAY instead fold `F_step` with plain Nova and prove the
`F_final` checks in a separate SNARK whose public input is the folded output.
It MUST then show that the composition is knowledge-sound.

**Uniform instantiation.** An implementation MAY place `F_start`, `F_step`
and `F_final` as branches of one uniform Nova step circuit. It selects the
branch from `pc` and a boolean `final` witness, and runs each unselected
branch on a fallback input whose output it discards. Every fold then pays for
all three branches, so this is slower than the SuperNova form but needs only
Nova's security argument. Its arithmetization name is `r1cs-nova-uniform`
(§10). The reference implementation uses this form with nova-snark 0.76.0,
whose documentation cites Nguyen, Boneh and Setty (2023) for its cycle
instantiation. Recursive proofs from this form carry real witnesses in every
branch, so they MUST NOT leave the prover.

The 2-cycle instantiation MUST have a published security proof. Nguyen, Boneh
and Setty (2023) prove a repaired Nova on a cycle; CycleFold gives a general
route for folding schemes. Neither proves SuperNova on a cycle as such, so an
implementation MUST state how SuperNova's knowledge soundness composes with
the cycle construction it uses.

### 9.2 Zero knowledge
Folding alone does not hide the witness. Before compression, the prover MUST
fold the final instance with a random satisfying instance and compress with a
zero-knowledge SNARK, as in Nova and HyperNova. Proofs use fresh prover
randomness. Only test fixtures may be deterministic.

### 9.3 Verification
1. Select pinned issuer and log keys (v0.2 §2 rules), and the pinned proof
   verification key. The verifier MUST pin, out of band, the circuit version,
   the proof-system version and the verification key, and MUST check that the
   receipt's `vk_digest` (§10) equals its pinned digest. It MUST NOT load a
   verification key from a receipt or from the prover: a key for another
   circuit could output the expected final state without checking anything.
2. Reject the receipt unless `algorithm` names an arithmetization and proof
   encoding the verifier implements, and `fold_count` is an allowed bucket
   (§11).
3. Build `headBytes` (§7.1) from the receipt's `log_root` and `tree_size`, and
   verify `log_head_signature` over it. The verifier MUST pass these same
   values to the proof verifier. It MUST NOT accept a head and a public input
   that differ in either value.
4. Verify the proof with `fold_count` steps from the initial state
   `(START, 0, public_bind, 0)`, built from the verifier's own expected values,
   and check that the output state is `(HALT, 0, public_bind, nullifier)`.
5. Check `issuer_key_commitment`, `policy_commitment` and `nullifier_scope`
   against the expected values.
6. Check and record `(nullifier_scope, nullifier)` in the scope's replay set as
   one atomic, persistent step, before returning a result. If the pair is new,
   the result is `SEALED CHECK PASSED`. If it is already present, the result is
   `SEALED REPLAY SUSPECTED`. If the step cannot complete, the verifier MUST
   fail closed.

Replay detection is best effort. It catches accidental reuse and naive replay.
A repeat is not a fraud proof, and a holder can claim the issuer reissued a
receipt. Only audit mode (§8.3) makes reissued receipts visible.

## 10. Public input and wire format

```text
PublicInput = {
  profile: "sar-zk-v0.4a" | "sar-zk-v0.4b",
  issuer_key_commitment: F,
  log_root: F, tree_size: DECIMAL, log_id: ID,
  log_head_signature: B64URL,          // Ed25519 over headBytes, 64 bytes
  policy_commitment: F,
  nullifier_scope: F,
  nullifier: F
}
SealedReceipt = { profile, public_input: PublicInput, proof: B64URL,
                  fold_count: DECIMAL,
                  algorithm: { arithmetization: "r1cs-nova-uniform" | "r1cs-supernova",
                               curve: "pasta",
                               proof_encoding: STRING,
                               vk_digest: HEX64 } }
```

All numbers are decimal strings (v0.2 §3.1). Unknown members, duplicate
members (after escape decoding) and JSON number tokens are rejected. The
top-level `profile` MUST equal `public_input.profile`.

- `fold_count` is the number of folds the proof covers: a power of two with
  `4 <= fold_count <= 2^20`.
- `arithmetization` names the construction (§9.1). `r1cs-supernova` is
  reserved; a verifier that does not implement it MUST reject it.
- `proof_encoding` names the exact byte encoding of `proof`. The reference
  value is `nova-snark-0.76.0/bincode-2.0.1-legacy`. Decoders MUST reject
  trailing bytes and decoded proofs over 64 KiB.
- `vk_digest` is SHA-256 over `"SAR-ZK-vk-digest-v0.4" || 0x00` and the
  encoded verification key, in lowercase hex. It identifies the key; it does
  not supply it (§9.3 step 1).

## 11. What the verifier sees (candidate set)

A verifier sees the full public input: the profile, the issuer key
commitment, the log, its root and size, the policy, the scope and the
nullifier. It also learns the number of folding steps, because IVC verifiers
take it as input. Holders MUST pad runs with padding steps up to a fixed
bucket, the next power of two at or above `T + 2` (at least 4), and MUST NOT
treat the bucket as private. Preparing the trace SHOULD take the same work for
padding and real steps, so presentation time does not reveal `T` within its
bucket. Zero knowledge hides the witness beyond this. It does not promise
that many records fit it. The **candidate set** is the set of records
compatible with all public information. It can be much smaller than the log,
and presentations under different policies or roots narrow it further. The
issuer can recognise the leaves of the statements it signed, but under the PRF
assumption the nullifier does not tell it which of them is being proven.
The candidate set depends on what the adversary knows, so a report MUST name
the adversary. It cannot be read from `tree_size`: a log signer can sign a
large `tree_size` over mostly empty positions. Counting filled positions gives
only an upper bound, because duplicate leaves add no records, and leaves do
not show a record's step-count bucket or whether it passes a policy. A real
figure needs the statements and inventories, so a report MUST say how it
opened, deduplicated and filtered them. Results MUST report candidate-set
sizes, and small sets MUST be reported as weak. This profile is designed to provide zero knowledge, not anonymity. No
external audit of it exists yet.

### 11.1 Adaptive verifiers
Each presentation tells the verifier one bit: the record meets the chosen
policy. A refusal tells it the same bit. Zero knowledge adds nothing beyond
that bit, but the bits add up. Let `C_0` be the candidate set before any
query. After `Q` answered or refused policies `P_1..P_Q` with outcomes
`a_1..a_Q`, the verifier can narrow it to

```text
C_Q = { R in C_0 : P_j(R) = a_j for every j }
```

The outcomes carry at most `Q` bits, but nothing bounds `|C_Q|` from below:
one bit can leave a single record. With free choice of policy, the allowlist
`U \ {D}` asks whether tool `D` ran, about 32 payment bounds give the exact
payment count by binary search, and one query gives the egress flag.

A holder wallet MUST apply these three controls:

1. **Policy classes.** The wallet proves only against policies from classes
   the holder or the deployment approved: allowlist roots from a registry, and
   payment bounds from a short fixed list of coarse thresholds. Arbitrary roots
   and arbitrary 32-bit bounds are what make interrogation cheap.
2. **Audit manifests.** Before the first presentation, the verifier sends an
   authenticated manifest that binds its identity, an audit identifier, the
   ordered list of policy commitments it will ask about, a maximum query count
   and an expiry. The scope SHOULD be `H_scope(verifier_id, audit_id)`. The
   wallet proves only against policies in the manifest.
3. **Budgets.** The wallet keeps, per `leaf(S)`, a persistent record of every
   policy it proved, refused or abandoned, per verifier and audit. Refusals
   count. The default budget is one policy per receipt per audit; more needs
   explicit holder consent. If the wallet cannot store the record, it MUST
   refuse to present.

No single control is enough. A manifest can list 32 binary-search bounds;
budgets cap the number of queries but not the harm of one well-chosen query;
verifiers that collude under different identities need a shared audit domain,
which the circuit cannot enforce. Reports MUST state the number of distinct
policies answered per record beside the candidate-set size.

## 12. Limits

- All v0.2 §1 negative scope markers carry over verbatim.
- Privacy is verifier-facing only. The holder and the issuer see the record.
- Policies are fixed-shape, count payments rather than value them, and rely on
  issuer-declared entries. Amounts, payees and time bounds are future work.
- The issuer labels each entry's kind. An issuer that records egress as a file
  entry makes a "nothing sent outside" policy pass. The cryptography cannot
  catch a wrong label.
- Without audit mode (§8.3), the holder chooses which receipts to present.
- Repeated queries leak up to one bit each (§11.1).
- Path requests can tell the log which receipt a holder controls (§8.1).
- Circuits are auditable, not proven safe. The status stays `draft` until an
  external audit accompanies a release.
- Normative Poseidon test vectors do not exist yet.
