# Sealed Receipts: Zero-Knowledge Policy Checks for AI Agent Task Records

By Lugano Labs. Draft v0.5 for public comment, 10 November 2026.

This paper specifies a construction and reports measurements of a profile-b
reference prover. The prover and the comparison have not been independently
audited. The normative details are in the SAR-ZK v0.4 profile; this paper
explains the design and the evidence.

## Abstract

When an AI agent finishes a task, such as reading mail, moving files or paying
an invoice, how can the people responsible for it prove the run followed a
policy without revealing what the agent did? Signed task records, or "agent
receipts", let anyone check that a record was signed and logged. But with a
plain signed record, you must read the whole record to check any fact about the
task.

We specify **Sealed Receipts**. With it, the holder of a receipt can convince a
verifier of three things without showing the record. A trusted issuer signed
it. It sits in a signed log. And it meets a policy the verifier picks: only
approved tools, nothing sent outside, and no more than a set number of
payments. The verifier also learns a *nullifier*. This value repeats if the
same receipt is shown twice in the same context. Under the assumptions in
Section 7, its values cannot be linked across contexts, though the rest of what
a verifier sees may still link two presentations.

The reference prover checks the record step by step and folds the steps into
one short proof. It uses uniform Nova over the Pallas/Vesta curve cycle and a
transparent Spartan SNARK with IPA compression. It needs no trusted setup. Its
zero-knowledge construction folds in random satisfying instances before
compression; the implementation has not been independently audited.

On one Apple M5 Max CPU, our 1,000-entry proof took 94.926 s to create and 63.9
ms to verify, and was 11,784 bytes long. The 63.9 ms is the proof check alone.
A new verifier process first spends about 6.2 s loading its 64.6 MB key. RISC
Zero's faster composite mode took 29,316 s for a test record of the same
length, about 308× our proving time. That was one run, on a machine that was
also in use. The proof covers the data the issuer declared, not what the agent
actually did.

## Lay summary

Say an AI agent has done work for you. It read your mail, moved some files and
made a payment. A signed record of that work exists. Normally, to prove
anything about the record, you have to show it. That exposes the private work
inside.

Sealed Receipts offer another way. Whoever holds the record can prove three
things without showing it: a trusted party signed it, it sits in a signed log,
and it followed the rules the checker cares about. Those rules can be "only
approved tools", "nothing sent outside" and "no more than three payments". The
checker learns those facts and one more: a code that shows up again if someone
presents the same record twice in the same context, such as one audit. Unless
the cryptography breaks or the holder's secret leaks, checkers in two different
contexts cannot match their codes to tell they saw the same record. Checkers
that share a context can. Other clues, such as a rare policy or the timing, may
still give it away.

The design has limits. It does not prove the agent really ran as described, or
that no data left the system. It proves that the record, as the signer wrote it
down, follows the rules. The building blocks come from privacy-preserving
cryptography, including tools Zcash uses to keep payments private.

We built a first working version and measured it on one computer, an Apple M5
Max, using only its processor. For a task of 1,000 steps, making the proof took
about 95 seconds. Checking it took about 64 milliseconds, and the proof is
about 12 kilobytes. The checking time and the proof size stayed about the same
from 10 steps to 1,000. The time to make the proof grew with the number of
steps.

We ran the same check in the faster mode of RISC Zero, a general-purpose system
that can prove any program. For a 100-step task it took about 55 minutes,
against just over 15 seconds for ours. For 1,000 steps it took about 8.1
hours, about 308 times our time. We ran that case once, while the computer was
also doing other work. Other work slows RISC Zero down, so a quiet computer
would give a smaller gap. We do not know by how much. A graphics card would
speed RISC Zero up, and we did not test one. Nobody outside has audited the
work yet.

## 1. Introduction

An agent receipt is a statement about one agent task, signed by an issuer. The
statement lists what the task touched: the tools it called, the places it sent
data, the files it used and the payments it made. Each item is a digest: a
fixed-length fingerprint of the artifact. The statement is also a leaf in a
signed Merkle log, so a verifier can check it was logged. Our Signed Agent
Receipt v0.2 is one such format, with an offline checker [1].

The problem is disclosure. To learn even one fact from such a receipt, such as
"no data left" or "only approved tools ran", the verifier must read the full
statement. It sees every digest and the whole inventory of private work.

So we ask: **what can be verified without recording someone's private work?**
One answer is to run the whole record check inside a general zero-knowledge
virtual machine (zkVM). That works, but a general-purpose machine is costly for
one fixed check. This paper specifies a purpose-built alternative.

Our contributions:

1. **A receipt format built for later policy checks.** The issuer signs a
   fixed-size statement that commits to the task's inventory as a hash chain.
   The holder can later prove that the inventory meets any policy of a fixed
   shape, even one the verifier chose after issuance (Section 5).
2. **A folding design and a built profile-b prover.** The cheaper design uses a
   small step circuit and a separate final circuit. The reference prover puts
   all three branches in one uniform Nova circuit and pays for each branch on
   every fold. We expect its timings to be an upper bound for the non-uniform
   design, which we did not build. The running state is blinded, so it does not
   fingerprint the receipt (Section 5.6). The nullifier is the one public value
   that is meant to repeat, and only within a scope.
3. **Scoped receipt nullifiers.** The nullifier depends on a holder secret and a
   verifier-chosen scope, not on the receipt's log position. Replay within a
   scope shows up; under the assumptions in Section 7, nullifier values in
   different scopes cannot be linked. An
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
online and willing to sign. Sealed Receipts are worth their cost only when one
of these holds:

- **The verifier picks the policy later.** An auditor chooses its tool
  allowlist and payment limit at audit time. The issuer cannot sign every
  possible allowlist in advance.
- **The issuer is offline or gone** when the check happens, or unwilling to
  sign a new statement for each verifier.
- **The issuer should not learn who checks, or against which policy.** A
  per-verifier compliance signature tells the issuer about every audit.

Neither design makes the issuer's declaration true. If the issuer lies about
the inventory, both designs carry the lie.

**When not to use this.** If the issuer is online, the policy is known when the
record is made, and the checks are routine, have the issuer sign "compliant".
It is simpler and cheaper. If you need to know what the agent actually did,
rather than what the issuer wrote down, use attested execution, such as a
trusted execution environment. If the policy needs amounts, payees, time
windows or arbitrary logic, use a general zkVM. It can express that today. Our
fixed policy shape cannot. Sealed Receipts fit a narrower case: long records,
policies chosen late or kept private, an issuer that may be gone, and verifiers
who should not see the content.

## 3. Related work

**Anonymous credentials.** Camenisch–Lysyanskaya [2] and BBS+ signatures [3, 4]
let a holder prove predicates over issuer-signed attributes without showing
them. BBS+ presentations cannot be linked to each other. A verifier nonce stops
a presentation from being replayed to the same verifier. The base scheme cannot
detect one credential shown twice in a context. It has no log membership and no
check over a per-task transcript. Coconut adds threshold issuance [5]. Two
older lines of work fill parts of that gap. Pseudonym systems [32] let a holder
deal with each organisation under a separate pseudonym that cannot be linked to
the others. Compact e-cash [33] gives each coin a serial number, so a second
spend is detected. Our scoped nullifier does for a receipt what that serial
number does for a coin. **zk-creds** [6] is the closest prior work: it issues
credentials to a bulletin board such as a transparency log and uses zkSNARKs to
prove membership and predicates, without needing an issuer signing key. Our
design differs in three ways. Each record carries an issuer signature over a
per-task transcript. The policy is checked over a sequence of entries by
folding. And the nullifier is per receipt. zkLogin [31] also proves in zero
knowledge that a user holds a token signed by an identity provider. It
authenticates a user for a blockchain transaction; it does not check a policy
over a task record.

**Scoped nullifiers.** Semaphore derives its nullifier from a member secret and
an "external nullifier", or scope [7]. The same member signalling twice in one
scope repeats the value; different scopes give unrelated values. Our
nullifier follows this pattern.

**Zcash.** Zerocash stopped double-spending without revealing which coin was
spent. It used a value it called a serial number [8]. Zcash calls that value a
nullifier. Zcash's Orchard pool works over the Pallas/Vesta cycle. It derives
nullifiers with Poseidon [9]. Its note commitments and Merkle tree use a
different hash, Sinsemilla. Halo first showed practical recursive proofs
without a trusted setup, on a cycle of ordinary elliptic curves [10].

**Folding and IVC.** Nova folds repeated instances of one circuit into a single
running instance [11]. SuperNova lets each step run one of several circuits,
and the step pays only for the circuit it runs [12]. HyperNova generalises the
approach [13]. ProtoStar builds folding schemes for a wider class of protocols
and also supports non-uniform steps [30]. We did not build on it. A 2023
analysis found a soundness flaw in Nova's original cycle-of-curves
implementation and proved a fixed version secure [14]. CycleFold is a later
design for the same job [15]. Spartan provides transparent SNARKs used to
compress folded proofs [16]. Poseidon is the in-circuit hash [17].

**zkVMs.** SP1 [18], the RISC Zero zkVM [19] and Jolt [20] prove arbitrary
programs. They offer generality we do not need. We expect a fixed relation to
be cheaper. This is a hypothesis, and Section 9 tests it.

**TLS attestation.** TLSNotary [21] and DECO [22] prove that data came from a
particular TLS server, with a notary or verifier taking part in the session.
They prove facts about one network session, not about a task that spans many
tools and sessions.

**Hardware attestation.** Trusted execution environments attest to a runtime's
measured state. An enclave can keep inputs private and release only a result.
That privacy depends on the hardware vendor and the enclave code, not on a
proof. They complement this work.

**Logs.** Certificate Transparency [23, 24] made signed, gossiped Merkle logs
practical. We use its gossip idea as a mitigation (Section 8). CONIKS brought
such logs to user keys. Its clients check that a provider shows everyone the
same log [34].

**Private audits.** In zkLedger, an auditor queries a private ledger, and the
banks cannot hide transactions from the audit [35]. Our audit mode aims at the
same completeness with a simpler tool, a per-account log, and it trusts the
issuer to log every receipt (Section 6).

**Agent records in zero knowledge.** Three 2026 works apply zero-knowledge
proofs to records of AI agents, as we do. ZK-Receipt [26] has a provider sign a
credential for one AI interaction. The holder then proves in zero knowledge
that an authorized provider and model signed it, without showing the prompt or
the response. Its prototype uses Circom and Groth16 [29]. AgentProof [27] is an
open-source proof of concept. It uses Groth16 to prove that a log of at most
eight tool calls follows a small set of rules. Authorization Without Disclosure
[28] proposes a zero-knowledge proof over an authorization decision whose
receipt body stays sealed; it reports no implementation. Our work differs in
scale and in evidence. We fold a policy check over a signed transcript of up to
1,000 entries with no trusted setup, and we publish measurements.

| Approach | What it proves | Rests on | Gap for agent records |
|---|---|---|---|
| Issuer-signed compliance | one fixed policy | issuer | policy fixed at issuance; a new policy needs the issuer again |
| BBS+ / CL credentials | predicates over signed attributes | issuer | base schemes have no log membership and no per-task transcript check |
| zk-creds | membership and predicates over logged credentials | log, proof system | no per-task transcript or folded policy check |
| zkVM | any computation | proof system | general-purpose cost (measured on CPU for this relation in Section 9) |
| TLS attestation | facts about one TLS session | notary or verifier, TLS | no task, log or policy structure |
| TEE attestation | a measured runtime | hardware vendor, enclave code | privacy rests on trusted hardware and enclave code, not on a proof |
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
policy at a time. Section 8 bounds what that reveals and how a holder's wallet
limits it. The log signer may be lazy or curious. It can shrink the set of
plausible records. At the extreme, it signs a tree with one leaf. Gossiping
heads helps, but we do not solve this. When a holder asks a log for a
membership path, the log learns which receipt the holder controls. So holders
should fetch paths early and in batches, never just before presenting.

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
commitment. `S` never holds the inventory itself. `S` has a fixed size, so the
signature check costs the same for a run of ten entries or ten thousand.

### 5.2 The transcript
Each inventory entry is a kind (tool, egress, file or payment) plus a digest,
split into two 128-bit field elements. The transcript is a Poseidon hash chain
that starts from the task binding and absorbs each entry with its position.
The issuer computes the final value and signs it in `S`. The holder keeps the
entries. Changing, dropping or reordering any entry changes the final value.

Our circuit ties `task_binding` to the run only through that signed value. The
prover supplies the task binding that starts the chain, and the chain must end
at the value the issuer signed. An honest issuer builds the chain from the
`task_binding` in `S`, so a different start would need a hash collision. An
issuer that signs a chain built from some other task binding is not caught by
the proof. The RISC Zero guest rebuilds the chain from the signed
`task_binding`, so it is stricter on this one point.

The gap gives a holder no forgery. The signature covers the final transcript
value and the step count, and the circuit enforces both. A holder would have to
forge the signature or find a second chain of the signed length that ends at
the signed value, which is a Poseidon collision. What the circuit misses is an
issuer that signs an inconsistent statement, and a pass already trusts the
issuer for what the record says.

A test in the repository gives the same records to both relations: the
constraints of our circuit, and the plain relation that the guest runs. It
makes no proofs. The two agree on honest records at six run lengths, and they
both reject eight changed records. They differ in only one tested case: a
record whose signed chain starts from another task binding. It passes our
constraints and fails the plain relation.

### 5.3 The policy
A policy is an allowlist of tool digests (the root of a depth-16 Merkle tree),
an egress flag and a payment bound. Its Poseidon commitment is public. The
verifier computes the commitment for the policy it wants and rejects any other.
Payment checks count payment entries. They do not bound amounts.

### 5.4 The log
The log is a new Poseidon Merkle tree of fixed depth 32, with separate hash
labels for leaves, internal nodes and empty positions. Its head is signed with
Ed25519 and checked outside the circuit. A v0.2 receipt cannot move into this
log. Records need fresh issuance.

### 5.5 Issuance
The holder picks a fresh random nullifier key `nk` for each receipt and a
random `r`, and sends only the commitment `H(nk, r)` to the issuer. Reusing
`nk` across receipts would turn the nullifier into a pseudonym for the holder,
so the profile forbids it. The issuer sees only the commitment, so it cannot
check this rule. A holder who breaks it harms their own receipts. Under one
scope, two of them give the same value, and the second looks like a replay. The
issuer builds and signs `S`, and the leaf goes into the log. The issuer never
sees `nk`. An issuer must not sign two statements for one task; nothing in the
design can detect it if one does.

### 5.6 Folding the run
The cheaper design uses non-uniform folding in the SuperNova style [12] with
three circuits. A start circuit is selected once: it checks the policy against
its public commitment and opens the running state. A step circuit is selected
once per entry: it checks the entry against the policy, extends the transcript
and counts payments. A final circuit is selected once: it checks that the
transcript and count match `S`, the payment bound, the issuer signature, the
log membership and the nullifier. It then sets a halt flag, which the verifier
checks. Without that check, a proof that never ran the final circuit would
pass. We have not built this non-uniform design yet.

In folding schemes the starting and final states are public. The final circuit
clears the running values (transcript, count, policy), so the public end state
holds only the public input and the nullifier. Inside the proof, the running
values sit in a hash with a random value that is fresh for every presentation.
With a zero-knowledge compression step, the verifier never sees the
intermediate states. So this blinding is defense in depth. It matters if a
recursive proof ever leaves the prover, which it must not. A test makes two
presentations of one receipt and checks that each uses a new random value and
starts from a different running state. A lower-level call builds the steps
without a presentation and keeps the old value. It exists for setup and
benchmarks, and the implementation notes say so.

Our reference prover uses uniform Nova from nova-snark 0.76.0. Vesta is the
primary curve and Pallas is the secondary curve. The three circuits are
branches of one circuit with 60,301 application constraints. Taken alone, the
start, step and final branches have 2,483, 12,806 and 45,046 constraints. Each
of these counts includes a 39-constraint check of the public values. The joined
circuit makes this check once. The logic that selects a branch adds 44. The sum
is 2,483 + 12,806 + 45,046 − 2 × 39 + 44 = 60,301. A test in the repository
measures each part and checks the sum.

Every fold runs all three branches. The `pc` value and a final flag select the
result. So every fold pays for the signature and log-membership constraints,
even though their branch is selected only once. That branch is about three
quarters of the circuit. This costs more than the SuperNova design, so we
expect our timings to be an upper bound for it. We did not build it, so we
cannot confirm this. The uniform circuit also avoids an open question: whether
SuperNova is secure on a curve cycle (Section 7).

The prover pads the fold count to the next power of two at or above `T + 2`.
The presented proof is a CompressedSNARK: Spartan with IPA on both curves.
Recursive proofs contain real witnesses in every branch and never leave the
prover. No SuperNova implementation was built or measured.

For the non-uniform design, each fold would pay only for its selected circuit.
The uniform implementation pays for all three. In both forms, proof size and
verification time should stay essentially flat as `T` grows. Section 9 tests
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
the prover must fold in a random satisfying instance. The nova-snark
documentation says this makes the proof zero-knowledge and points to the
HyperNova paper for the details [13]. That fold is what hides the witness. We
rely on that paper for the argument; we did not prove it again. The reference prover calls
nova-snark's CompressedSNARK. We inspected that code: it samples and folds
random satisfying instances on both curves before Spartan compression. The
presentation API also samples fresh accumulator blinding from the operating
system for every proof. This is the implemented zero-knowledge construction, not
an independent security proof.

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
  replay. If the issuer signs the same task again under a new nullifier key,
  the second receipt gives a new value and no repeat shows. If it signs again
  under the same key, a repeat shows, and the holder can say it is the second
  receipt, not a replay. Outside audit mode, a verifier cannot tell the two
  cases apart.
- **The log position does not matter.** If the log index were part of the
  nullifier, the same record logged twice would yield two values and slip past
  replay checks. The nullifier depends only on `nk` and the scope, so this
  cannot happen.

Verifiers who share a scope share replay detection, and they also learn when
the same receipt was shown to each of them. That is the trade. Each deployment
must say which verifiers share a scope.

**Audit mode.** Normally the holder chooses which receipts to show. So the
auditor learns only that the shown records comply. Audit mode closes that gap
without changing the circuit. The issuer logs every receipt for one account in
an account log that the holder does not run. The log rejects duplicates. The
auditor fixes that log's signed head for the period end, with `n` leaves, and
one scope. The holder must then present `n` passing proofs with `n` different
nullifiers. Each logged record can yield only one nullifier per scope, so `n`
different nullifiers cover every leaf. A failing record cannot be proven, so a
missing proof means a withheld or failing record. The auditor learns `n` and
whose records these are; it still learns nothing about what they say. Audit
mode still trusts the issuer to log every receipt, and it trusts the log's
signer to keep every leaf. Audit mode is a design. The repository does not
implement it.

## 7. Security argument (sketch)

This is a sketch, not a proof.

- **Soundness.** The cheaper SuperNova design would need a knowledge-soundness
  proof for its composition with a cycle of curves. Nguyen, Boneh and Setty
  proved a repaired Nova on a cycle [14], and CycleFold gives a general route
  [15]. Neither covers SuperNova directly. The uniform design we built does not
  claim that composition. It relies on the repaired Nova cycle argument of
  [14]. The nova-snark documentation says the library implements that
  instantiation. We read the verifier in version 0.76.0. It recomputes a hash
  over each of the two running instances and rejects a proof whose last step
  does not carry both hashes. We did not compare the code with [14] line by
  line, and we did not audit the library. Both designs also rest on
  collision resistance of Poseidon over the Pallas base field, for the
  transcript, the tree and the commitments; binding of the nullifier-key
  commitment, which follows from collision resistance; and unforgeability of
  Schnorr over Pallas (profile b) or of Ed25519 with strict verification
  (profile a). Fiat–Shamir is applied as in the underlying schemes.
- **Zero knowledge** rests on the hiding compression step: the prover folds in
  a random satisfying instance before a Spartan compression [11, 13, 16]. The
  public start and end states carry no witness data. Blinding the running state
  is defense in depth. It treats fixed-length Poseidon with a uniform random
  input as a hiding commitment. That is an assumption, not a consequence of
  collision resistance. Our reference prover relies on the compression step in
  nova-snark. We checked that the code performs it. That is not a proof that
  the step is secure.
- **Nullifier privacy** assumes Poseidon keyed by a secret, uniformly random
  `nk` behaves as a PRF across scopes. An efficient adversary that picks scopes
  adaptively and sees many outputs must not tell them from random, even when
  it also holds the commitment `H(nk, r)`. Collision resistance alone does not
  give this.
- **Leaf privacy.** Log leaves are hashes of `S`, and `S` includes the
  commitment `H(nk, r)` with a fresh random `r`. Under the same hiding
  assumption as above, a leaf shows that some record exists but not what it
  says, and an outsider cannot test a guessed record without `r`. This protects
  against guessing only. Anyone who later learns `S` can compute its leaf. The
  issuer knows `S`, so it can recognise its own leaves; the nullifier still
  hides which of them is being proven.

An internal security review added several implementation checks. The verifier
pins a verification-key digest and checks the proof's algorithm fields. It
builds the signed log head from the same root and tree size that it passes to
the proof verifier. Its persistent replay set checks and inserts a nullifier in
one atomic step, and it fails closed on storage errors. Each presentation
samples fresh accumulator blinding from the operating system. Native padding
computes the same transcript-step hash as a real step and discards the result.
The uniform circuit does the same work for both. A test feeds the proof and key
decoders 1,537 malformed byte streams of up to 64 KiB each. No decoder
panicked, and none held more than 2,105,349 bytes at one time. We did not test
malformed key files above 64 KiB. The repository also holds test vectors for
the hashes and the receipt format. They come from this code, and no second
implementation has confirmed them. These checks do not amount to an external
audit.

A full cryptographic proof, an independently verified circuit and an external
audit are all still to come. Until they exist, the points above are assumptions,
not theorems.

## 8. What the verifier learns

The verifier sees the public input: the profile, the issuer key commitment,
the log and its root and size, the policy commitment, the scope and the
nullifier. It also learns the number of folding steps, because folding
verifiers take it as input. The reference prover pads each run up to the next
power of two, and the reference verifier rejects a step count that is not a
power of two from 4 through 2^20. So the verifier learns only a size bucket,
not the exact length.

Zero knowledge hides everything else. It does not promise that many records fit
what is public. The records that match all public information form the
**candidate set**. It can be much smaller than the log, and presentations under
different policies or roots narrow it further. A log signer that signs tiny
trees can shrink it to one. A signer can also sign a large tree size over
mostly empty positions. So the tree size alone can overstate the set. Counting
filled positions gives only an upper bound. A real figure needs the records
themselves. It also depends on what the adversary already knows.

Our native benchmark fixture has 16 synthetic receipts with the same issuer,
policy and public run-length bucket. That is a weak structural candidate count,
not a deployment anonymity measurement. The recorded deterministic seed exposes
the fixture witnesses. An adversary with that seed can open them. So these runs
demonstrate neither witness privacy nor anonymity. Log leaves are not an
anonymity-set claim.

**Many questions.** Each presentation tells the verifier one bit: the record
meets this policy. A refusal can tell it something too, though a holder may
also refuse because a budget ran out or the policy is not approved. Zero
knowledge adds nothing beyond that bit, but the bits add up. After `Q` policies
the verifier has at most `Q` bits from the answers themselves, and nothing
stops those bits from pointing to a single record. This count leaves out what
timing, error messages and the public inputs may add. If the auditor may choose
any policy, it can ask "does the allowlist without tool D still pass?" once per
tool. The payment count can't exceed the padded step count the verifier
already learns, so a binary search over payment bounds finds it in about 11
queries at 1,000 entries and never more than 21. It can
learn the egress flag in one question. So the holder's wallet, not the circuit,
must limit what it answers. It proves only against approved policy classes:
allowlists from a registry and a short list of coarse payment bounds. It asks
the auditor to commit in advance to the list of policies for an audit. And it
keeps a budget per receipt, by default one policy per audit, in which refusals
count. No single control suffices. Together they bound the leak. Reports should
state how many policies each record answered. The specification requires these
controls. The reference code has no wallet, so none of them is built or tested
here.

## 9. Experiment and results

### 9.1 Design stated in advance

The following design and hypotheses were stated before measurement. Their
wording is unchanged. This is our own account: we did not register them with a
third party, and this repository's history starts after every measurement but
two: the 1,000-entry RISC Zero run and the whole-command timing of
`zkar verify`. Section 9.2 describes both.

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
    This follows from the folding scheme. Failure would mean an implementation
    error.
  - H2: at 1,000 entries, our prover is at least ten times faster than the zkVM
    on the same relation. If it is not, the case for a purpose-built relation is
    weak, and we will say so.
  - H3: the final circuit dominates cost for short runs, and the step circuit
    for long ones. We will report where they cross.
- **Profile a.** We will report the cost of the Ed25519 final circuit
  separately, so readers can see what Ed25519 compatibility costs.

### 9.2 Actual setup and method

We built profile b with uniform Nova. We did not use SuperNova. Section 5.6
explains the reason and the extra cost. Profile a was not built.

All measurements used one Apple M5 Max with 18 CPU cores and 128 GB of memory
on macOS. All provers used the CPU only. The native run used Rust 1.94.0,
nova-snark 0.76.0 and bincode 2.0.1 legacy encoding without compression. The
zkVM run used RISC Zero 3.0.6 and bincode 1.3 receipt encoding.

For folded, monolithic and per-entry proving, every system and size had three
runs. Each run used a fresh process. We report the median of each metric on its
own. So the component medians need not add up to the total median. Setup is
separate from proving. Folded proving time is recursive folding plus
compression. Peak RSS covers the whole fresh worker process. Proof sizes omit
verification keys and public-input transport.

The native fixtures are synthetic and use a recorded seed. They contain 16
receipts with the same issuer, policy and public run-length bucket. This count
is only a weak structural check. It is not an anonymity measurement. The
recorded seed exposes the witnesses.

The per-entry baseline emits `T + 1` proofs. It has no authenticated chaining
and no secure start/end composition. So it costs less than a secure
composition. Its reported size is the sum of the individual proof encodings,
without container framing. The monolithic and per-entry baselines use the
direct Spartan APIs. These do not perform the random satisfying-instance fold.
We claim no zero knowledge for those baselines. They also omit privacy padding.

The RISC Zero guest checks the same relation, with one difference: it rebuilds
the chain from the signed task binding, so it is stricter on that point
(Section 5.2). A test checks the two relations against each other on shared
small records. The two provers ran test records of the same length but not the
same content. Both mix tool, file, payment and egress entries. Ours repeats one
approved tool, sets the payment bound to the run length, and uses a log of 16
signed leaves. The baseline uses 3, 25 and 250 distinct tools, sets the payment
bound to the payment count plus one, and has logs of 13, 103 and 1,003 leaves.
So the speed factors below compare two different sets of records. They do not
come from one shared input. The guest uses the bigint2 accelerator for Pallas
arithmetic and embedded Poseidon constants. It does not implement folding, the
outer Ed25519 log-head check, replay storage or the full receipt wire protocol.
Its host checks the receipt against the expected journal. RISC Zero proves
arbitrary programs. Our prover handles one fixed relation. That generality is
part of what the baseline pays for.

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

RISC Zero proved the `T = 1,000` case once, in composite mode. We stopped one
earlier attempt after 47 minutes, because another job was using a large share
of the CPU. It produced no proof and no timing. Other programs also shared the
CPU during the run that we report. We sampled the load every five minutes with
`ps`. Over the 97 samples taken after launch, the prover held a mean of 1,620%
CPU out of 1,800%. The log's first line is the sample at launch. Other programs
took a mean of 102%, with a peak of 706%. Shared load slows RISC Zero, so this
run favours our system by an amount we cannot state. We made the other runs,
ours and RISC Zero's, with no other heavy work on the machine, but we kept no
load log for them.

RISC Zero did not prove the succinct `T = 1,000` case. For that mode, we draw a
straight line in total cycles through the `T = 10` median and the `T = 100`
run. We then read the line at 749,207,552 cycles. An execution-only run and the
composite proof run both report that count. Only the succinct `T = 1,000`
proving time is an estimate. We do not estimate its other missing metrics.

Both systems ran on the same CPU. RISC Zero 3.0.6's Apple Metal path is
disabled in its source, and we did not test CUDA. Our build also replaces the
unused Metal asset with an empty file, because the machine lacked Apple's Metal
build tools; the baseline README gives the details. We expect a GPU to cut RISC
Zero's proving time substantially. These measurements cannot say by how much.

Native verification times cover the SNARK checks and output comparison. They
exclude Ed25519 log-head verification, proof decoding, verification-key pinning
and replay storage. The RISC Zero times cover receipt verification. So these
are core-proof comparisons. They are not full sealed-receipt request timings.

After the benchmark runs, we timed the whole `zkar verify` command on a
10-entry record. We ran the command 10 times. Each run started a new process
with a new replay file, on a machine in use. The median was about 6.5 s, with a
range of 6.47 s to 6.74 s. Loading the verification key takes about 6.2 s of
that. The key is a 64.6 MB file, and decoding it takes about 5.95 s. That
leaves about 0.3 s for all other steps: parsing, the log-head signature, proof
decoding, the SNARK check and the replay record. A verifier that stays running
loads the key once. We timed one record size only.

### 9.3 Native results

Times are medians of three fresh-process runs. Verification is in milliseconds;
peak RSS is in bytes. Each cell is rounded to the last digit shown; the raw
records hold the exact values.

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

Folded proving beats both direct baselines already at `T = 10`. Its proof is
larger than the monolithic proof, and its peak memory is higher than per-entry
proving. At `T = 1,000`, monolithic setup takes 405.149895 s, peak RSS reaches
70,747,422,720 bytes (about 70.7 GB), and verification takes 4.917643 s. These
are not hidden costs of the folded system, but they show why the table reports
setup and memory as well as proving time.

### 9.4 RISC Zero results

At `T = 10`, each value is the median of three runs. At `T = 100`, it is the
one run that we made. At `T = 1,000`, the composite row is one run on a
machine in use (Section 9.2). The succinct proving time is an estimate, not a
measurement. A dash means that no proof metric was measured.

| T | Mode | Proof runs | Prove (s) | Verify (ms) | Receipt bytes | Peak RSS | Total cycles |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | composite | 3 | 795.330032625 | 223.140833 | 5,628,192 | 11,206,426,624 | 20,971,520 |
| 10 | succinct | 3 | 955.412304042 | 8.975834 | 225,018 | 11,206,459,392 | 20,971,520 |
| 100 | composite | 1 | 3,311.618415375 | 879.667333 | 22,225,718 | 11,186,831,360 | 82,837,504 |
| 100 | succinct | 1 | 4,087.643700459 | 9.063584 | 225,018 | 11,208,867,840 | 82,837,504 |
| 1,000 | composite | 1 (machine in use) | 29,316.134718709 | 7,674.066292 | 201,128,174 | 14,368,112,640 | 749,207,552 |
| 1,000 | succinct | 0 | 37,825.492 (estimate) | — | — | — | 749,207,552 |

The succinct estimate uses the displayed, unrounded inputs:

```text
4087.643700459
+ (749207552 - 82837504)
  * (4087.643700459 - 955.412304042)
  / (82837504 - 20971520)
= 37825.492046611... s
```

Before we ran the composite case, the same method gave this estimate for it:

```text
3311.618415375
+ (749207552 - 82837504)
  * (3311.618415375 - 795.330032625)
  / (82837504 - 20971520)
= 30415.029724487... s
```

The measured composite time, 29,316.134 s, is 3.6% lower than that estimate,
even with the shared load. The straight line overstated the composite time. The
succinct estimate may be too high in the same way.

At the two sizes where we measured it, 10 and 100 entries, RISC Zero's succinct
receipt verifies in about 9 ms, faster than our 60 to 64 ms. Its receipt is
225,018 bytes against our 11,784 bytes. We lose on verification speed and win on
proof size in this comparison. The composite receipt grows with the run. At `T =
1,000` it is 201,128,174 bytes and takes 7.674 s to verify.

### 9.5 Hypothesis verdicts

- **H1: supported by the measurements.** Folded proof size is 11,784 bytes at
  all three sizes. Median verification stays between 59.9 and 64.3 ms from 10
  to 1,000 entries. We set no tolerance for "flat" in advance; the highest
  median is about 7% above the lowest. This is a result for these fixtures and
  this machine, not a proof about every run length. The hypothesis said a
  failure would mean an implementation error. That was too strong, because
  timing noise alone could also break flatness.
- **H2: supported by the measurements.** Against composite RISC Zero, folded
  proving is 163.100 times faster at `T = 10`, 216.483 times faster at `T =
  100` and 308.831 times faster at `T = 1,000`. The `T = 100` and `T = 1,000`
  factors each come from one RISC Zero run, so we have no run-to-run spread for
  them. The `T = 1,000` run was on a machine in use, so a quiet machine would
  give a lower factor. One run cannot bound the effect of the load. The prover
  held a mean of 90% of the CPU, and the `T = 100` run, made without that load,
  already gives a factor of about 216. We therefore do not expect the load to
  change the verdict. The corresponding succinct factors are 195.928, 267.212
  and an estimated 398.473. We truncated every factor to three decimal places.
  We never rounded one up. All exceed the factor of ten stated in advance. H2
  said "on the same relation" and named no hardware. What we tested is
  narrower: the guest is stricter on the task binding, the two provers ran
  different test records (Section 9.2), and all results are CPU-only. The
  verdict holds for that test.
- **H3: not testable as written.** Uniform Nova has no separate final circuit
  in the measured implementation. Every fold includes all three branches. We
  have not rewritten the hypothesis after the fact. The closest measured
  comparison is recursive folding against compression.

The H3 comparison uses the padded fold counts 16, 128 and 1,024. Per-fold time
is recursive time divided by fold count. The last column is compression time
divided by that per-fold time. These ratios combine medians that were reported
independently. They are descriptive arithmetic, not new measurements. We
computed them from the rounded values shown.

| T | Folds | Recursive (s) | Recursive per fold (ms) | Compression (s) | Compression / per-fold (folds) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 16 | 1.467377 | 91.711063 | 3.375707 | 36.808068 |
| 100 | 128 | 11.438193 | 89.360883 | 3.805185 | 42.582223 |
| 1,000 | 1,024 | 91.511533 | 89.366731 | 3.414359 | 38.206153 |

For example, at `T = 100`, `11.438193 / 128 = 0.0893608828125` s per fold and
`3.805185 / 0.0893608828125 = 42.582222559...` folds. The other rows use the
same arithmetic. Compression stays in a narrow 3.375707–3.805185 s range while
recursive folding grows. Folding is below compression at 16 folds and above it
at 128 folds. The ratios imply a crossing at about 37–43 folds. That would fall
in the 64-fold bucket. We did not measure that bucket.

Separately, folded proving already beats monolithic and per-entry proving at `T
= 10`. It stays faster at all three measured sizes. Profile a has no results.
We did not build its Ed25519 final circuit.

### 9.6 Threats to validity

- All runs used one machine and CPU proving only. Other hardware can change the
  result. RISC Zero's Metal path is disabled in this version, CUDA was untested,
  and a GPU baseline could be much faster by an unknown amount.
- RISC Zero has three proof runs at `T = 10` but only one at `T = 100`. The
  latter has no measured run-to-run spread.
- The `T = 1,000` composite RISC Zero time is one run on a machine in use.
  Shared load slowed it by an unknown amount. That favours us. It has no
  measured run-to-run spread. The succinct `T = 1,000` time is a straight-line
  cycle estimate, not a proof measurement.
- RISC Zero proves arbitrary programs. Our system proves one fixed relation.
  The guest also omits the outer receipt protocol. Receipt encodings and
  verification scopes differ, as described above.
- Per-entry proving is not a secure composition. It lacks authenticated
  chaining and is deliberately cheaper than one. The direct baselines omit
  privacy padding and the random satisfying-instance fold, so they do not have
  the folded system's zero-knowledge guarantee.
- The fixtures are synthetic and use fixed inventory mixes. The two provers did
  not run one shared input (Section 9.2). The native candidate count is a weak
  structural count of 16. Its recorded seed exposes the witnesses. These runs
  demonstrate neither deployment anonymity nor witness privacy.
- Three native runs per configuration give limited evidence about variance.
  Each metric has its own median. Fresh-process peak RSS includes work outside
  the timers.
- The verification times in the tables exclude log-head verification, proof
  decoding, key loading and replay storage. The whole command took about 6.5 s
  on a 10-entry record, and loading the verification key took almost all of it
  (Section 9.2). That is one record size, on a machine in use.
- The benchmark run recorded dependency versions and raw logs but no source
  revision. The implementation has not been independently audited.

## 10. Limits

1. A sealed receipt covers declared data. It is not evidence of execution,
   observation, retention or time.
2. Privacy holds against the verifier only. The holder and the issuer can see
   the record.
3. Policies have a fixed shape. General policy languages are future work.
4. Circuit bugs are possible. We keep the relation small so it can be audited.
   After an audit we will say "audited", never "proven safe".
5. The candidate set, not the log size, bounds what the verifier cannot tell
   apart.
6. The issuer could sign two statements for one task and so give the holder two
   nullifiers. Only issuance discipline prevents this. In audit mode the extra
   receipt adds one to the count, but the auditor cannot tell that two receipts
   cover one task.
7. Outside audit mode, the holder chooses which receipts to show.
8. Each answered policy leaks one bit, and a refusal can leak too. The
   specification requires wallet controls that limit this, but we have not
   built them here. The circuit cannot limit it.
9. The issuer labels each entry's kind. An issuer that records data sent
   outside as a file entry makes "nothing sent outside" pass.
10. Policies count payments but cannot cap their value, check payees or bound
    time. These are future work.
11. The measured uniform prover repeats every branch on every fold. We have not
    built or measured the cheaper SuperNova design or profile a.
12. The comparison uses synthetic fixtures and one CPU. The two provers ran
    test records of the same length but not the same content. The 1,000-entry
    composite RISC Zero time is one run under shared load. The succinct time is
    an estimate. GPU proving is unmeasured.
13. Folded proving is not best on every metric. RISC Zero's succinct receipt
    verifies in about 9 ms (measured at 10 and 100 entries) against our 60 to
    64 ms, but it is 225,018 bytes against our 11,784 bytes. The monolithic
    proof is smaller than ours: 7,928 bytes against 11,784 at 1,000 entries.
    Per-entry proving uses less peak memory in these runs.

## Claims

| Claim | Status | Where |
|---|---|---|
| The relation fits a fixed set of circuits | Built for profile b; 60,301 uniform application constraints; not independently audited | Sections 5 and 9 |
| A proof cannot omit or reorder entries | Argued and exercised by implementation tests; not independently audited | Sections 5.2 and 5.6 (transcript equality, halt flag) |
| Proof size and verify time stay essentially flat as runs grow | Measured at 10, 100 and 1,000 entries on one CPU | Section 9, H1 |
| No trusted setup | Inherited from Nova-family schemes and Spartan | [11, 12, 16] |
| Zero knowledge | Built with random satisfying-instance folds in nova-snark; not independently audited | Sections 5.6 and 7 |
| Replay within a scope is detected | Implemented with an atomic replay set; best effort, and a holder can claim reissue | Section 6 |
| Nullifier values are unlinkable across scopes | Argued, assuming keyed Poseidon is a PRF even to a holder of `H(nk, r)` and that the presented proof is zero-knowledge; whole presentations may still link | Section 6 |
| Audit mode shows every receipt of an account was presented | Argued; not implemented; trusts the issuer to log every receipt and the log's signer to keep every leaf | Section 6 |
| Faster than a zkVM on this relation | Measured at 10, 100 and 1,000, on test records of the same length but not one shared input; the 1,000 run is one run on a machine in use; CPU only | Section 9, H2 |
| Timings and sizes | Measured for profile b and the baselines; RISC Zero succinct proving at 1,000 is estimated | Section 9 |
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
13. A. Kothapalli and S. Setty. "HyperNova: Recursive Arguments for Customizable Constraint Systems." CRYPTO 2024. ePrint 2023/573.
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
26. A. Emami Neishabouri, A. Sartipi, J. Schönrich and I. Tchappi. "ZK-Receipt: Privacy-Preserving Verifiable Provenance for Intermediated AI Services." Workshop "Who Verifies the Agents? Toward Reliable Agent Development", NeurIPS 2026. https://neurips.cc/virtual/2026/172956
27. *AgentProof: zero-knowledge verification of AI agent policy compliance* (proof of concept). 2026. https://github.com/dvelton/agentproof
28. A. Hasbini. *Authorization Without Disclosure: An advisory reference architecture for non-disclosing agent-to-agent authorization.* Version 1.1, 2026. doi:10.5281/zenodo.23515310
29. J. Groth. "On the Size of Pairing-Based Non-interactive Arguments." EUROCRYPT 2016. ePrint 2016/260.
30. B. Bünz and B. Chen. "ProtoStar: Generic Efficient Accumulation/Folding for Special Sound Protocols." ASIACRYPT 2023. ePrint 2023/620.
31. F. Baldimtsi, K. K. Chalkias, Y. Ji, J. Lindstrøm, D. Maram, B. Riva, A. Roy, M. Sedaghat and J. Wang. "zkLogin: Privacy-Preserving Blockchain Authentication with Existing Credentials." ACM CCS 2024. arXiv:2401.11735.
32. A. Lysyanskaya, R. L. Rivest, A. Sahai and S. Wolf. "Pseudonym Systems." Selected Areas in Cryptography (SAC) 1999. LNCS 1758, pp. 184–199.
33. J. Camenisch, S. Hohenberger and A. Lysyanskaya. "Compact E-Cash." EUROCRYPT 2005. LNCS 3494, pp. 302–321.
34. M. S. Melara, A. Blankstein, J. Bonneau, E. W. Felten and M. J. Freedman. "CONIKS: Bringing Key Transparency to End Users." USENIX Security 2015.
35. N. Narula, W. Vasquez and M. Virza. "zkLedger: Privacy-Preserving Auditing for Distributed Ledgers." USENIX NSDI 2018.
