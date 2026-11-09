# Sealed Receipts: Zero-Knowledge Policy Checks for AI Agent Task Records

By Lugano Labs. Draft v0.5 for public comment, 9 November 2026.

This paper specifies a construction and reports measurements of a profile-b
reference prover. The prover and the comparison have not been independently
audited. The normative details are in the SAR-ZK v0.4 profile; this paper
explains the design and the evidence.

## Abstract

When an AI agent finishes a task, such as reading mail, moving files or paying
an invoice, how can the people responsible for it prove the run followed a
policy without revealing what the agent did? Signed task records, or "agent
receipts", let anyone check that a record was signed and logged. Today, though,
checking any fact about the task means reading the whole record.

We specify **Sealed Receipts**. With it, the holder of a receipt can convince a
verifier of three things without showing the record. A trusted issuer signed
it. It sits in a signed log. And it meets a policy the verifier picks: only
approved tools, nothing sent outside, and no more than a set number of
payments. The verifier also learns a *nullifier*, a value that repeats if the
same receipt is shown twice in the same context. Its values cannot be linked
across contexts, though the rest of what a verifier sees may still link two
presentations.

The reference prover uses uniform Nova over the Pallas/Vesta curve cycle and a
transparent Spartan SNARK with IPA compression. It needs no trusted setup. Its
zero-knowledge construction folds in random satisfying instances before
compression; the implementation has not been independently audited.

On one Apple M5 Max CPU, our 1,000-entry proof took 94.926 s to create and
63.893 ms to verify, and was 11,784 bytes long. A cycle-based estimate puts
RISC Zero's faster composite mode at 30,415 s (about 320× our proving time), but we
did not prove that 1,000-entry case. The proof covers the data the issuer
declared, not what the agent actually did.

## Lay summary

Say an AI agent has done work for you. It read your mail, moved some files and
made a payment. A signed record of that work exists. Normally, to prove
anything about the record, you have to show it, and that exposes the private
work inside.

Sealed Receipts offer another way. Whoever holds the record can prove three
things without showing it: a trusted party signed it, it sits in a signed log,
and it followed the rules the checker cares about. Those rules can be "only
approved tools", "nothing sent outside" and "no more than three payments". The
checker learns those facts and one more: a code that shows up again if someone
presents the same record twice to the same checker. Two different checkers
cannot match their codes to tell they saw the same record, though other clues,
such as a rare policy or the timing, may still give it away.

The design has limits. It does not prove the agent really ran as described, or
that no data left the system. It proves that the record, as the signer wrote it
down, follows the rules. The building blocks come from privacy-preserving
cryptography, including tools Zcash uses to keep payments private.

We built a first working version and measured it on one computer, an Apple M5
Max, using only its processor. For a task of 1,000 steps, making the proof took
about 95 seconds. Checking it took about 64 milliseconds, and the proof is
about 12 kilobytes. Both stayed about the same from 10 steps to 1,000.

We ran the same check in the faster mode of RISC Zero, a general-purpose system
that can prove any program. For a 100-step task it took about 55 minutes,
against just over 15 seconds for ours. For 1,000 steps we estimate about 8.4
hours for RISC Zero, about 320 times our time. We did not run that case. A
graphics card would speed RISC Zero up, and we did not test one. Nobody outside
has audited the work yet.

## 1. Introduction

An agent receipt records that an issuer signed a statement about an agent task.
The statement lists what the task touched: the tools it called, the places it
sent data, the files it used and the payments it made. Each item is a digest, a
fixed-length fingerprint of the artifact. The statement is also a leaf in a
signed Merkle log, so a verifier can check it was logged. Our Signed Agent
Receipt v0.2 is one such format, with an offline checker [1].

The problem is disclosure. To learn even one fact, such as "no data left" or
"only approved tools ran", the verifier must read the full statement. It sees
every digest and the whole inventory of private work.

So we ask: **what can be verified without recording someone's private work?**
One answer is to run the whole record check inside a general zero-knowledge
virtual machine (zkVM). That works, but it pays general-purpose costs for one
fixed check. This paper specifies a purpose-built alternative.

Our contributions:

1. **A receipt format built for later policy checks.** The issuer signs a
   fixed-size statement that commits to the task's inventory as a hash chain.
   The holder can later prove that the inventory meets any policy of a fixed
   shape, even one the verifier chose after issuance (Section 5).
2. **A folding design and a built profile-b prover.** The cheaper design uses a
   small step circuit and a separate final circuit. The reference prover puts
   all three branches in one uniform Nova circuit and pays for each branch on
   every fold. Its timings are an upper bound for the non-uniform design. The
   public state is blinded, so it does not fingerprint the receipt (Section
   5.6).
3. **Scoped receipt nullifiers.** The nullifier depends on a holder secret and a
   verifier-chosen scope, not on the receipt's log position. Replay within a
   scope shows up; nullifier values in different scopes cannot be linked. An
   audit mode uses them to check that a holder showed every receipt in a
   period (Section 6).
4. **A threat model, a privacy analysis and measurements** against hypotheses
   stated before the experiment (Sections 7 to 9).

We do not claim a new primitive. Every part comes from prior work, mostly from
anonymous credentials, Zcash and folding schemes. The contribution is fitting
them to agent task records and stating exactly what the result proves and what
it does not.

## 2. Why not have the issuer sign "compliant"?

The issuer is trusted for the record's content and sees all of it. So the
simplest design is for the issuer to sign one more statement: "record X meets
policy P". The verifier checks one signature and learns one fact. No circuits
are needed.

That design wins whenever the policy is known at issuance and the issuer is
online and willing to sign. Sealed Receipts earn their cost only when one of
these holds:

- **The verifier picks the policy later.** An auditor chooses its tool
  allowlist and payment limit at audit time. The issuer cannot sign every
  possible allowlist in advance.
- **The issuer is offline or gone** when the check happens, or unwilling to
  sign a new statement for each verifier.
- **The issuer should not learn who checks, or against which policy.** A
  per-verifier compliance signature tells the issuer about every audit.

Neither design makes the issuer's declaration true. If the issuer lies about
the inventory, both designs carry the lie.

**When not to use this.** If the issuer is online, the policy is known when
the record is made, and the checks are routine, have the issuer sign
"compliant". It is simpler and cheaper. If you need to know what the agent
actually did, rather than what the issuer wrote down, use attested execution,
such as a trusted execution environment. If the policy needs amounts, payees,
time windows or arbitrary logic, a general zkVM can express it today and our
fixed policy shape cannot. Sealed Receipts fit a narrower case: long records,
policies chosen late or kept private, an issuer that may be gone, and
verifiers who should not see the content.

## 3. Related work

**Anonymous credentials.** Camenisch–Lysyanskaya [2] and BBS+ signatures [3, 4]
let a holder prove predicates over issuer-signed attributes without showing
them. BBS+ presentations cannot be linked to each other. A verifier nonce stops
a presentation from being replayed to the same verifier, but BBS+ has no
built-in way to detect the same credential shown to two verifiers, and no
built-in log membership. Coconut adds threshold issuance [5]. **zk-creds** [6]
is the closest prior work: it issues credentials to a bulletin board such as a
transparency log and uses zkSNARKs to prove membership and predicates, without
needing an issuer signing key. Our design differs in three ways. Each record
carries an issuer signature over a per-task transcript. The policy is checked
over a sequence of entries by folding. And the nullifier is per receipt.

**Scoped nullifiers.** Semaphore derives its nullifier from a member secret and
an "external nullifier", or scope [7]. The same member signalling twice in one
scope repeats the value; different scopes give unrelated values. Our
nullifier follows this pattern.

**Zcash.** Zerocash introduced nullifiers to stop double-spending without
revealing which note was spent [8]. Zcash's Orchard pool works over the
Pallas/Vesta cycle and derives nullifiers with Poseidon [9]. Its note
commitments and Merkle tree use a different hash, Sinsemilla. Halo showed
recursive proofs without a trusted setup on this cycle [10].

**Folding and IVC.** Nova folds repeated instances of one circuit into a single
running instance [11]. SuperNova lets each step run one of several circuits,
paying only for the one it runs [12]. HyperNova generalises the approach [13].
A 2023 analysis found a soundness flaw in Nova's original cycle-of-curves
implementation and proved a fixed version secure [14]; CycleFold is a later
design for the same job [15]. Spartan provides transparent SNARKs used to
compress folded proofs [16]. Poseidon is the in-circuit hash [17].

**zkVMs.** SP1 [18], the RISC Zero zkVM [19] and Jolt [20] prove arbitrary
programs. They buy generality we do not need. We expect a fixed relation to be
cheaper, but this is a hypothesis, and Section 9 tests it.

**TLS attestation.** TLSNotary [21] and DECO [22] prove that data came from a
particular TLS server, with a notary or verifier taking part in the session.
They prove facts about one network session, not about a task that spans many
tools and sessions.

**Hardware attestation.** Trusted execution environments attest to a runtime's
measured state. They rest on the hardware vendor and give the verifier no
cryptographic privacy. They complement this work.

**Logs.** Certificate Transparency [23, 24] made signed, gossiped Merkle logs
practical. We use its gossip idea as a mitigation (Section 8).

| Approach | What it proves | Rests on | Gap for agent records |
|---|---|---|---|
| Issuer-signed compliance | one fixed policy | issuer | policy fixed at issuance; issuer sees every check |
| BBS+ / CL credentials | predicates over signed attributes | issuer | no log membership; no cross-verifier replay detection |
| zk-creds | membership and predicates over logged credentials | log, proof system | no per-task transcript or folded policy check |
| zkVM | any computation | proof system | general-purpose cost (measured on CPU for this relation in Section 9) |
| TLS attestation | facts about one TLS session | notary or verifier, TLS | no task, log or policy structure |
| TEE attestation | a measured runtime | hardware vendor | no privacy from the verifier |
| Signed Agent Receipt v0.2 | signature and log membership | issuer, log signer | full disclosure |

## 4. Setting and trust model

**Running example.** A company's finance team runs a payroll agent. The
agent's tool calls pass through a gateway run by a separate provider. The
gateway is the **issuer**: for each run, it signs a task record listing what
passed through it, and adds the record to a log. A **log signer** signs the
log's heads. Months later an outside auditor, the **verifier**, asks the finance
team, the **holder**, to show that each run used only approved tools, sent
nothing outside and made at most three payments. The auditor picks that policy
at audit time. The gateway provider is not involved. The policy counts
payments; it cannot cap their value, so an auditor who needs amounts must wait
for a richer policy (Section 10).

**Adversary.** The prover is malicious: it may try to prove a record that was
not signed, not logged or not compliant. Soundness must stop it. The verifier
is honest but curious: it should learn nothing beyond the public input (zero
knowledge, Section 7). A curious verifier can still ask many questions, one
policy at a time; Section 8 bounds what that reveals and how a holder's wallet
limits it. The log signer may be lazy or curious: it can shrink the
set of plausible records, at the extreme by signing a tree with one leaf.
Gossiping heads mitigates this; we do not solve it. A log also learns which
receipt a holder controls when the holder asks it for a membership path, so
holders should fetch paths early and in batches, never just before presenting.

**What a sealed receipt does not prove.** It does not prove that the agent ran,
that a digest matches a real artifact, that the inventory is complete, that
data was kept or deleted, or what time it was. These limits carry over from
v0.2 unchanged [1]. A sealed receipt proves only this: *some record, signed by
a trusted issuer and included in a signed log, meets the stated policy.*

## 5. Construction

This section summarises the design. The SAR-ZK v0.4 profile gives every
encoding, label and check.

### 5.1 The statement
The issuer signs a fixed-size statement `S` with five fields: a profile tag, a
`task_binding` that commits to the task's metadata, the number of inventory
entries `T`, the final transcript value, and the holder's nullifier-key
commitment. `S` never holds the inventory itself. Because `S` has a fixed size,
the signature check costs the same for a run of ten entries or ten thousand.

### 5.2 The transcript
Each inventory entry is a kind (tool, egress, file or payment) plus a digest,
split into two 128-bit field elements. The transcript is a Poseidon hash chain
that starts from the task binding and absorbs each entry with its position.
The issuer computes the final value and signs it in `S`. The holder keeps the
entries. Changing, dropping or reordering any entry changes the final value.

### 5.3 The policy
A policy is an allowlist of tool digests (the root of a depth-16 Merkle tree),
an egress flag and a payment bound. Its Poseidon commitment is public. The
verifier computes the commitment for the policy it wants and rejects any other.
Payment checks count payment entries; they do not bound amounts.

### 5.4 The log
The log is a new Poseidon Merkle tree of fixed depth 32, with separate hash
labels for leaves, internal nodes and empty positions. Its head is signed with
Ed25519 and checked outside the circuit. A v0.2 receipt cannot move into this
log; records need fresh issuance.

### 5.5 Issuance
The holder picks a fresh random nullifier key `nk` for each receipt and a
random `r`, and sends only the commitment `H(nk, r)` to the issuer. Reusing
`nk` across receipts would turn the nullifier into a pseudonym for the holder,
so the profile forbids it. The issuer builds and signs `S`, and
the leaf goes into the log. The issuer never sees `nk`. An issuer must not sign
two statements for one task; nothing in the design can detect it if one does.

### 5.6 Folding the run
The cheaper design uses non-uniform folding in the SuperNova style [12] with
three circuits. A start circuit is selected once: it checks the policy against
its public commitment and opens the running state. A step circuit is selected
once per entry: it checks the entry against the policy, extends the transcript
and counts payments. A final circuit is selected once: it checks that the
transcript and count match `S`, the payment bound, the issuer signature, the
log membership and the nullifier. It then sets a halt flag, which the verifier
checks. Without that check, a proof that never ran the final circuit would
pass. This non-uniform design remains future work.

In folding schemes the starting and final states are public. The final circuit
clears the running values (transcript, count, policy), so the public end state
holds only the public input and the nullifier. Inside the proof, the running
values sit in a hash with a random value that is fresh for every presentation.
With a zero-knowledge compression step the verifier never sees the intermediate
states, so this blinding is defense in depth; it matters if a recursive proof
ever leaves the prover, which it must not.

Our reference prover uses uniform Nova from nova-snark 0.76.0. Vesta is the
primary curve and Pallas is the secondary curve. The three circuits are
branches of one circuit with 60,301 application constraints. Every fold runs
all three branches. The `pc` value and a final flag select the result. Every
fold therefore pays for the signature and log-membership constraints, even
though their branch is selected only once. This costs more than the SuperNova
design and makes our timings an upper bound for that design. It also avoids
the open question of SuperNova's security on a curve cycle (Section 7).

The prover pads the fold count to the next power of two at or above `T + 2`.
The presented proof is a CompressedSNARK: Spartan with IPA on both curves.
Recursive proofs contain real witnesses in every branch and never leave the
prover. No SuperNova implementation was built or measured.

For the non-uniform design, each fold would pay only for its selected circuit.
The uniform implementation pays for all three. In both forms, proof size and
verification time should stay essentially flat as `T` grows; Section 9 tests
this. Prover time and the holder's stored entries grow with `T`. The holder can
fold entries as they arrive, but the final proof waits for the issuer's
signature.

**Signature profiles.** Profile b, our first target, uses a Schnorr signature
over Pallas, which is native to the circuit's field. Profile a verifies Ed25519
in the circuit, which needs non-native arithmetic and SHA-512. One public
Ed25519 verification circuit has about 2.5 million R1CS constraints [25]. We
cite that figure as an estimate of scale; we have not measured our own.
Profile a was not built, so we report no measurement for its final circuit.

**Zero knowledge.** Folding alone does not hide the witness. Before compression,
the prover must fold in a random satisfying instance and compress with a
zero-knowledge SNARK, as Nova and HyperNova describe [11, 13]. The reference
prover calls nova-snark's CompressedSNARK. We inspected that code: it samples
and folds random satisfying instances on both curves before Spartan
compression. The presentation API also samples fresh accumulator blinding from
the operating system for every proof. This is the implemented zero-knowledge
construction, not an independent security proof.

## 6. Nullifiers

The nullifier is `H(nk, scope)`, where the verifier chooses the scope, for
example a hash of its own identifier and the audit's purpose.

- **Replay within a scope shows up.** Proving the same receipt twice under one
  scope gives the same value. A verifier that keeps a set sees the repeat. A
  repeat is an alarm, not proof of fraud: the holder may have had a good reason
  to show the record again.
- **Nullifier values in different scopes cannot be linked**, provided
  Poseidon keyed by `nk` behaves as a pseudorandom function and `nk` stays
  secret. This covers the nullifier only. A shared scope, the rest of the public
  input, a small candidate set, timing or colluding verifiers can still link
  two presentations. A verifier that wants no replay detection at all uses a
  fresh random scope each time.
- **Replay detection is best effort.** It catches accidental reuse and naive
  replay. A holder caught repeating a receipt can claim the issuer reissued it,
  and outside audit mode no one can tell.
- **The log position does not matter.** If the log index were part of the
  nullifier, the same record logged twice would yield two values and slip past
  replay checks. The nullifier depends only on `nk` and the scope, so this
  cannot happen.

Verifiers who share a scope share replay detection, and they also learn when
the same receipt was shown to each of them. That is the trade. Each deployment
must say which verifiers share a scope.

**Audit mode.** Normally the holder chooses which receipts to show, so an
auditor learns only that the shown records comply. Audit mode closes that gap
without changing the circuit. The issuer logs every receipt for one account in
an account log that the holder does not run, and the log rejects duplicates.
The auditor fixes that log's signed head for the period end, with `n` leaves,
and one scope. The holder must then present `n` passing proofs with `n`
different nullifiers. Each logged record can yield only one nullifier per
scope, so `n` different nullifiers cover every leaf. A failing record cannot be
proven, so a missing proof means a withheld or failing record. The auditor
learns `n` and whose records these are; it still learns nothing about what
they say. Audit mode still trusts the issuer to log every receipt.

## 7. Security argument (sketch)

This is a sketch, not a proof.

- **Soundness.** The cheaper SuperNova design would need a knowledge-soundness
  proof for its composition with a cycle of curves. Nguyen, Boneh and Setty
  proved a repaired Nova on a cycle [14], and CycleFold gives a general route
  [15]. Neither covers SuperNova directly. The built uniform instantiation does
  not claim that composition; it relies on Nova's cycle argument instead. Both
  designs also rest on collision resistance of Poseidon over the Pallas base
  field, for the transcript, the tree and the commitments; binding of the
  nullifier-key commitment, which follows from collision resistance; and
  unforgeability of Schnorr over Pallas (profile b) or of Ed25519 with strict
  verification (profile a). Fiat–Shamir is applied as in the underlying
  schemes.
- **Zero knowledge** rests on the hiding compression step: the prover folds
  in a random satisfying instance before a Spartan compression [11, 13, 16].
  The public start and end states carry no witness data. Blinding the running
  state is defense in depth, and it treats fixed-length Poseidon with a
  uniform random input as a hiding commitment, which is an assumption, not a
  consequence of collision resistance. Our reference prover relies on the
  compression step in nova-snark; we checked that the code performs it, which
  is not a proof that it is secure.
- **Nullifier privacy** assumes Poseidon keyed by `nk` behaves as a PRF across
  scopes. Collision resistance alone does not give this.
- **Leaf privacy.** Log leaves are hashes of `S`, and `S` includes the
  commitment `H(nk, r)` with a fresh random `r`. Under the same hiding
  assumption as above, a leaf shows that some record exists but not what it
  says, and an outsider cannot test a guessed record without `r`. This protects
  against guessing only: anyone who later learns `S` can compute its leaf. The
  issuer knows `S`, so it can recognise its own leaves; the nullifier still
  hides which of them is being proven.

An internal security review led to several implementation checks. The verifier
pins a verification-key digest and checks the proof's algorithm fields. It
builds the signed log head from the same root and tree size that it passes to
the proof verifier. Its persistent replay set checks and inserts a nullifier
atomically and fails closed on storage errors. Each presentation samples fresh
accumulator blinding from the operating system. Native padding computes the
same transcript-step hash as a real step and discards the result; the uniform
circuit does the same work for both. These checks do not amount to an external
audit.

A full cryptographic proof, an independently verified circuit and an external
audit are all still to come. Until they exist, the points above are assumptions,
not theorems.

## 8. What the verifier learns

The verifier sees the public input: the profile, the issuer key commitment,
the log and its root and size, the policy commitment, the scope and the
nullifier. It also learns the number of folding steps, because folding
verifiers take it as input. Holders should pad each run up to the next power of
two, so the verifier learns only a size bucket, not the exact length.

Zero knowledge hides everything else, but it does not promise that many
records fit what is public. We call the records that match all public
information the **candidate set**. It can be much smaller than the log, and
presentations under different policies or roots narrow it further. A log
signer that signs tiny trees can shrink it to one. It can also sign a large
tree size over mostly empty positions, so the tree size alone can overstate
the set. Counting filled positions gives only an upper bound: a real figure
needs the records themselves, and depends on what the adversary already knows.

Our native benchmark fixture has 16 synthetic receipts with the same issuer,
policy and public run-length bucket. That is a weak structural candidate count,
not a deployment anonymity measurement. The recorded deterministic seed exposes
the fixture witnesses. An adversary with that seed can open them, so these runs
demonstrate neither witness privacy nor anonymity. Log leaves are not an
anonymity-set claim.

**Many questions.** Each presentation tells the verifier one bit: the record
meets this policy. A refusal tells it the same bit. Zero knowledge adds nothing
beyond that bit, but the bits add up. After `Q` policies the verifier has at
most `Q` bits, and nothing stops those bits from pointing to a single record.
With a free choice of policy, an auditor can ask "does the allowlist without
tool D still pass?" once per tool, find the exact payment count with about 32
payment bounds, and learn the egress flag in one question. So the holder's
wallet, not the circuit, must limit what it answers. It proves only against
approved policy classes: allowlists from a registry and a short list of coarse
payment bounds. It asks the auditor to commit in advance to the list of
policies for an audit. And it keeps a budget per receipt, by default one policy
per audit, in which refusals count. No one control suffices; together they
bound the leak, and reports should state how many policies each record
answered.

## 9. Experiment and results

### 9.1 Pre-registered design

The following design and hypotheses were stated before measurement. Their
wording is unchanged.

We will build profile b first and measure it.

- **Setup.** A Rust prover with SuperNova-style folding over Pasta, Poseidon
  with the Orchard parameters, and the three circuits above. Fixtures with 10,
  100 and 1,000 entries, using recorded seeds for fixtures only.
- **Metrics.** Prover time, peak memory, proof size and verification time.
- **Baselines.** (a) One SNARK per entry, without folding. (b) One monolithic
  SNARK over the whole run. (c) A zkVM running the same relation. We treat the
  zkVM as a fair comparison: it buys generality we do not need.
- **Hypotheses, stated in advance.**
  - H1: proof size and verification time stay flat from 10 to 1,000 entries.
    This follows from the folding scheme; failure would mean an implementation
    error.
  - H2: at 1,000 entries, our prover is at least ten times faster than the zkVM
    on the same relation. If it is not, the case for a purpose-built relation is
    weak, and we will say so.
  - H3: the final circuit dominates cost for short runs, and the step circuit
    for long ones. We will report where they cross.
- **Profile a.** We will report the cost of the Ed25519 final circuit
  separately, so readers can see what Ed25519 compatibility costs.

### 9.2 Actual setup and method

We built profile b with uniform Nova, not SuperNova. Section 5.6 explains the
reason and the extra cost. Profile a was not built.

All measurements used one Apple M5 Max with 18 CPU cores and 128 GB of memory
on macOS. All provers used the CPU only. The native run used Rust 1.94.0,
nova-snark 0.76.0 and bincode 2.0.1 legacy encoding without compression. The
zkVM run used RISC Zero 3.0.6 and bincode 1.3 receipt encoding.

For folded, monolithic and per-entry proving, every system and size had three
runs. Each run used a fresh process. We report the median of each metric
independently, so component medians need not add up to the total median. Setup
is separate from proving. Folded proving time is recursive folding plus
compression. Peak RSS covers the whole fresh worker process. Proof sizes omit
verification keys and public-input transport.

The native fixtures are synthetic and use a recorded seed. They contain 16
receipts with the same issuer, policy and public run-length bucket. This weak
structural count is not an anonymity measurement. The seed exposes the
witnesses.

The per-entry baseline emits `T + 1` proofs. It has no authenticated chaining
or secure start/end composition, so it costs less than a secure composition.
Its reported size is the sum of the individual proof encodings, without
container framing. The direct Spartan APIs used for monolithic and per-entry
proving do not perform the random satisfying-instance fold. We claim no zero
knowledge for those baselines. They also omit privacy padding.

The RISC Zero guest checks the same relation. It uses the bigint2 accelerator
for Pallas arithmetic and embedded Poseidon constants. It does not implement
folding, the outer Ed25519 log-head check, replay storage or the full receipt
wire protocol. Its host checks the receipt against the expected journal. RISC
Zero proves arbitrary programs; our prover handles one fixed relation. That
generality is part of what the baseline pays for.

RISC Zero used `ProverOpts::default()` for composite receipts and
`ProverOpts::succinct()` for succinct receipts. At `T = 10`, each mode had three
fresh-process runs. At `T = 100`, each mode had one run. We use
`proof_generation` for proving time, `receipt_verify` for verification time,
`bincode_1_3_bytes` for receipt size, process peak RSS and `total_cycles`.
Proof generation includes guest execution and all work inside
`prove_with_opts`. It excludes fixture generation, native checks,
serialization, verification and artifact I/O. RISC Zero setup is not separately
measured. Verification runs after proving in the same process and may benefit
from warm caches.

RISC Zero did not prove the `T = 1,000` case. Its 749,207,552 cycles come from
an execution-only run. For each receipt mode separately, we draw a straight
line in total cycles through the `T = 10` median and the `T = 100` run, then
evaluate it at those cycles. Only the `T = 1,000` proving times are estimates.
We do not estimate its other missing metrics.

Both systems ran on the same CPU. RISC Zero 3.0.6's Apple Metal path is
disabled in its source, and we did not test CUDA. A GPU would cut RISC Zero's
proving time substantially; these measurements cannot say by how much.

Native verification times cover the SNARK checks and output comparison. They
exclude Ed25519 log-head verification, proof decoding, verification-key pinning
and replay storage. The RISC Zero times cover receipt verification. These are
therefore core-proof comparisons, not full sealed-receipt request timings.

### 9.3 Native results

Times are medians of three fresh-process runs. Verification is in milliseconds;
peak RSS is in bytes.

| System | T | Setup (s) | Prove (s) | Verify (ms) | Proof bytes | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| folded | 10 | 4.172260 | 4.876322 | 59.950 | 11,784 | 785,907,712 |
| folded | 100 | 4.217821 | 15.297333 | 64.204 | 11,784 | 797,360,128 |
| folded | 1,000 | 4.277097 | 94.925892 | 63.893 | 11,784 | 673,251,328 |
| monolithic | 10 | 6.077716 | 6.666265 | 103.544 | 6,056 | 1,453,588,480 |
| monolithic | 100 | 57.841601 | 47.909980 | 496.239 | 6,992 | 11,669,864,448 |
| monolithic | 1,000 | 405.149895 | 410.484430 | 4,917.643 | 7,928 | 70,747,422,720 |
| per-entry | 10 | 1.780428 | 6.365334 | 171.854 | 53,512 | 459,292,672 |
| per-entry | 100 | 2.093910 | 48.858484 | 1,403.516 | 486,232 | 665,190,400 |
| per-entry | 1,000 | 2.246029 | 510.513591 | 13,575.153 | 4,813,432 | 636,977,152 |

Folded proving is faster than both direct baselines already at `T = 10`. Its
proof is larger than the monolithic proof, and its peak memory is higher than
per-entry proving. At `T = 1,000`, monolithic setup takes 405.149895 s, peak
RSS reaches 70,747,422,720 bytes (about 70.7 GB), and verification takes
4.917643 s. These are not hidden costs of the folded system, but they show why
the comparison includes setup and memory as well as proof time.

### 9.4 RISC Zero results

At `T = 10`, each value is the median of three runs. At `T = 100`, it is the
single completed run. The two `T = 1,000` proving times are estimates, not
measurements. A dash means that no proof metric was measured.

| T | Mode | Proof runs | Prove (s) | Verify (ms) | Receipt bytes | Peak RSS | Total cycles |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | composite | 3 | 795.330032625 | 223.140833 | 5,628,192 | 11,206,426,624 | 20,971,520 |
| 10 | succinct | 3 | 955.412304042 | 8.975834 | 225,018 | 11,206,459,392 | 20,971,520 |
| 100 | composite | 1 | 3,311.618415375 | 879.667333 | 22,225,718 | 11,186,831,360 | 82,837,504 |
| 100 | succinct | 1 | 4,087.643700459 | 9.063584 | 225,018 | 11,208,867,840 | 82,837,504 |
| 1,000 | composite | 0 | 30,415.030 (estimate) | — | — | — | 749,207,552 |
| 1,000 | succinct | 0 | 37,825.493 (estimate) | — | — | — | 749,207,552 |

The estimate uses the displayed, unrounded inputs. For composite:

```text
3311.618415375
+ (749207552 - 82837504)
  * (3311.618415375 - 795.330032625)
  / (82837504 - 20971520)
= 30415.029724487... s
```

For succinct:

```text
4087.643700459
+ (749207552 - 82837504)
  * (4087.643700459 - 955.412304042)
  / (82837504 - 20971520)
= 37825.492046611... s
```

RISC Zero's succinct receipt verifies in about 9 ms, faster than our roughly
64 ms. Its receipt is 225,018 bytes against our 11,784 bytes. We lose on
verification speed and win on proof size in this comparison.

### 9.5 Hypothesis verdicts

- **H1: supported by the measurements.** Folded proof size is 11,784 bytes at
  all three sizes. Median verification stays between 59.950 and 64.204 ms from
  10 to 1,000 entries. This is a result for these fixtures and this machine,
  not a proof about every run length.
- **H2: supported, with an estimated 1,000-entry comparison.** Against
  composite RISC Zero, folded proving is 163.100 times faster at `T = 10` and
  216.483 times faster at `T = 100`. The estimated factor at `T = 1,000` is
  320.408. The corresponding succinct factors are 195.928, 267.212 and an
  estimated 398.473. All exceed the pre-registered factor of ten. The measured
  results cover 10 and 100 entries; the 1,000-entry result depends on the
  cycle extrapolation and is CPU-only.
- **H3: not testable as written.** Uniform Nova has no separate final circuit
  in the measured implementation. Every fold includes all three branches. We
  have not rewritten the hypothesis after the fact. The closest measured
  comparison is recursive folding against compression.

The H3 comparison uses the padded fold counts 16, 128 and 1,024. Per-fold time
is recursive time divided by fold count. The last column is compression time
divided by that per-fold time. These ratios combine independently reported
medians; they are descriptive arithmetic, not new measurements.

| T | Folds | Recursive (s) | Recursive per fold (ms) | Compression (s) | Compression / per-fold (folds) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 16 | 1.467377 | 91.711063 | 3.375707 | 36.808068 |
| 100 | 128 | 11.438193 | 89.360883 | 3.805185 | 42.582223 |
| 1,000 | 1,024 | 91.511533 | 89.366732 | 3.414359 | 38.206153 |

For example, at `T = 100`, `11.438193 / 128 = 0.0893608828125` s per fold and
`3.805185 / 0.0893608828125 = 42.582222559...` folds. The other rows use the
same arithmetic. Compression stays in a narrow 3.375707–3.805185 s range while
recursive folding grows. Folding is below compression at 16 folds and above it
at 128 folds. The ratios imply a crossing around 37–43 folds, which would put
it in the 64-fold bucket. We did not measure that bucket.

Separately, folded proving already beats monolithic and per-entry proving at
`T = 10`. It remains faster at all three measured sizes. Profile a has no
results because its Ed25519 final circuit was not built.

### 9.6 Threats to validity

- All runs used one machine and CPU proving only. Other hardware can change the
  result. RISC Zero's Metal path is disabled in this version, CUDA was untested,
  and a GPU baseline could be much faster by an unknown amount.
- RISC Zero has three proof runs at `T = 10` but only one at `T = 100`. The
  latter has no measured run-to-run spread.
- The `T = 1,000` RISC Zero proving times are straight-line cycle estimates.
  They are not proof measurements. The cycle count itself comes from execution.
- RISC Zero proves arbitrary programs, while our system proves one fixed
  relation. The guest also omits the outer receipt protocol. Receipt encodings
  and verification scopes differ, as described above.
- Per-entry proving is not a secure composition. It lacks authenticated
  chaining and is deliberately cheaper than one. The direct baselines omit
  privacy padding and the random satisfying-instance fold, so they do not have
  the folded system's zero-knowledge guarantee.
- The fixtures are synthetic and use fixed inventory mixes. The native
  candidate count is a weak structural count of 16, and its recorded seed
  exposes the witnesses. These runs demonstrate neither deployment anonymity
  nor witness privacy.
- Three native runs per configuration give limited evidence about variance.
  Each metric has its own median, and fresh-process peak RSS includes work
  outside the timers.
- Native verification excludes log-head verification, proof decoding and replay
  storage. Full request latency will be higher.
- The benchmark run recorded dependency versions and raw logs but no source
  revision. The implementation has not been independently audited.

## 10. Limits

1. A sealed receipt covers declared data. It is not evidence of execution,
   observation, retention or time.
2. Privacy faces the verifier only. The holder and the issuer see the record.
3. Policies have a fixed shape. General policy languages are future work.
4. Circuit bugs are possible. We keep the relation small so it can be audited,
   and after an audit we will say "audited", never "proven safe".
5. The candidate set, not the log size, bounds what the verifier cannot tell
   apart.
6. The issuer could sign two statements for one task and so give the holder
   two nullifiers. Only issuance discipline prevents this; audit mode at least
   makes the extra receipt visible.
7. Outside audit mode, the holder chooses which receipts to show.
8. Each answered or refused policy can leak one bit. Wallet controls limit
   this; the circuit cannot.
9. The issuer labels each entry's kind. An issuer that records data sent
   outside as a file entry makes "nothing sent outside" pass.
10. Policies count payments but cannot cap their value, check payees or bound
    time. These are future work.
11. The measured uniform prover repeats every branch on every fold. The cheaper
    SuperNova design and profile a remain unbuilt and unmeasured.
12. The comparison uses synthetic fixtures and one CPU. The 1,000-entry RISC
    Zero proving times are estimates, and GPU proving is unmeasured.
13. Folded proving is not best on every metric. RISC Zero's succinct receipt
    verifies in about 9 ms against our roughly 64 ms, but it is 225,018 bytes
    against our 11,784 bytes. The monolithic proof is smaller, and per-entry
    proving uses less peak memory in these runs.

## Claims

| Claim | Status | Where |
|---|---|---|
| The relation fits a fixed set of circuits | Built for profile b; 60,301 uniform application constraints; not independently audited | Sections 5 and 9 |
| A proof cannot omit or reorder entries | Argued and exercised by implementation tests; not independently audited | Sections 5.2 and 5.6 (transcript equality, halt flag) |
| Proof size and verify time stay essentially flat as runs grow | Measured at 10, 100 and 1,000 entries on one CPU | Section 9, H1 |
| No trusted setup | Inherited from Nova-family schemes and Spartan | [11, 12, 16] |
| Zero knowledge | Built with random satisfying-instance folds in nova-snark; not independently audited | Sections 5.6 and 7 |
| Replay within a scope is detected | Implemented with an atomic replay set; best effort, and a holder can claim reissue | Section 6 |
| Nullifier values are unlinkable across scopes | Argued, under the PRF assumption; whole presentations may still link | Section 6 |
| Audit mode shows every receipt of an account was presented | Argued; trusts the issuer to log every receipt | Section 6 |
| Faster than a zkVM on this relation | Measured at 10 and 100; estimated at 1,000; CPU only | Section 9, H2 |
| Timings and sizes | Measured for profile b and the baselines; RISC Zero proving at 1,000 is estimated | Section 9 |
| Candidate-set sizes | 16 synthetic native candidates; weak structural count, not deployment anonymity; zkVM candidate set unknown | Sections 8 and 9 |

## References

1. Lugano Labs. *Signed Agent Receipt Reference Profile v0.2.* 2026. https://github.com/Lugano-AI/signed-agent-receipt
2. J. Camenisch and A. Lysyanskaya. "An Efficient System for Non-transferable Anonymous Credentials with Optional Anonymity Revocation." EUROCRYPT 2001.
3. M. H. Au, W. Susilo and Y. Mu. "Constant-Size Dynamic k-TAA." SCN 2006.
4. S. Tessaro and C. Zhu. "Revisiting BBS Signatures." EUROCRYPT 2023.
5. A. Sonnino, M. Al-Bassam, S. Bano, S. Meiklejohn and G. Danezis. "Coconut: Threshold Issuance Selective Disclosure Credentials with Applications to Distributed Ledgers." NDSS 2019.
6. M. Rosenberg, J. White, C. Garman and I. Miers. "zk-creds: Flexible Anonymous Credentials from zkSNARKs and Existing Identity Infrastructure." IEEE S&P 2023. ePrint 2022/878.
7. Privacy & Scaling Explorations. *Semaphore protocol documentation.* https://docs.semaphore.pse.dev
8. E. Ben-Sasson, A. Chiesa, C. Garman, M. Green, I. Miers, E. Tromer and M. Virza. "Zerocash: Decentralized Anonymous Payments from Bitcoin." IEEE S&P 2014.
9. D. Hopwood, S. Bowe, T. Hornby and N. Wilcox. *Zcash Protocol Specification.* Electric Coin Company. https://zips.z.cash/protocol/protocol.pdf
10. S. Bowe, J. Grigg and D. Hopwood. "Recursive Proof Composition without a Trusted Setup." ePrint 2019/1021.
11. A. Kothapalli, S. Setty and I. Tzialla. "Nova: Recursive Zero-Knowledge Arguments from Folding Schemes." CRYPTO 2022. ePrint 2021/370.
12. A. Kothapalli and S. Setty. "SuperNova: Proving Universal Machine Executions without Universal Circuits." ePrint 2022/1758.
13. A. Kothapalli and S. Setty. "HyperNova: Recursive Arguments for Customizable Constraint Systems." ePrint 2023/573.
14. W. Nguyen, D. Boneh and S. Setty. "Revisiting the Nova Proof System on a Cycle of Curves." AFT 2023. ePrint 2023/969.
15. A. Kothapalli and S. Setty. "CycleFold: Folding-scheme-based Recursive Arguments over a Cycle of Elliptic Curves." ePrint 2023/1192.
16. S. Setty. "Spartan: Efficient and General-Purpose zkSNARKs without Trusted Setup." CRYPTO 2020. ePrint 2019/550.
17. L. Grassi, D. Khovratovich, C. Rechberger, A. Roy and M. Schofnegger. "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems." USENIX Security 2021. ePrint 2019/458.
18. Succinct. *SP1 documentation.* https://docs.succinct.xyz
19. RISC Zero. *RISC Zero zkVM documentation.* https://dev.risczero.com
20. A. Arun, S. Setty and J. Thaler. "Jolt: SNARKs for Virtual Machines via Lookups." EUROCRYPT 2024. ePrint 2023/1217.
21. TLSNotary project. https://tlsnotary.org
22. F. Zhang, D. Maram, H. Malvai, S. Goldfeder and A. Juels. "DECO: Liberating Web Data Using Decentralized Oracles for TLS." ACM CCS 2020.
23. B. Laurie, A. Langley and E. Kasper. *Certificate Transparency.* RFC 6962, 2013.
24. B. Laurie, E. Messeri and R. Stradling. *Certificate Transparency Version 2.0.* RFC 9162, 2021.
25. Electron Labs. *ed25519-circom: Ed25519 signature verification in circom* (unaudited research code). https://github.com/Electron-Labs/ed25519-circom
