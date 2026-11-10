# Implementation notes for SAR-ZK v0.4

This is an unaudited reference
implementation, not a claim that the construction or its dependencies have
been independently proven secure.

## §3.2: Orchard parameters across field-library versions

`halo2_poseidon` 0.2.0 uses `ff` 0.14 and `pasta_curves` 0.6.1; Nova uses
`ff` 0.13 and `halo2curves` 0.9.0. Constants are converted by canonical
little-endian field representations, with checked decoding. The native
permutation is independently implemented from those constants and compared
against Orchard's permutation on boundary and random states. The circuit
keeps round additions and MDS multiplication as linear combinations. A
materialized three-output permutation has 243 constraints: 240 S-box
multiplications and three output equalities. The sponge can carry linear
combinations between permutations and materializes only its final digest.
There is no parameter or sponge deviation from §3.2.

## §3.4: complete Pallas arithmetic and scalar representation

Nova's `AllocatedPoint` is parameterized by the curve's base field, so the
Pallas point gadget is `AllocatedPoint<PallasEngine>`, even though the primary
IVC engine is Vesta. Nova's optimized `scalar_mul` uses incomplete addition
for most bits. This implementation instead uses the public complete
`add`, `double`, and conditional-selection gadgets for every scalar bit.
Inputs are constrained on-curve and nonidentity. Invalid inputs are routed
to a canonical identity fallback for arithmetic while independent validity
constraints reject them, avoiding division-by-zero witness failures.

The response scalar is 255 explicit Fq bits with `s < q`; it is never packed
into Fp. This matters because valid scalars in `[p,q)` cannot fit in Fp.
The challenge uses a strict canonical Fp decomposition. Tests cover the
scalar boundaries `p`, `q-1`, and `q`, and the same-group-element encoding
`s+q`. Native signing samples nonzero scalars from a caller-supplied CSPRNG;
the explicit-nonce primitive is documented as a low-level fixture helper.

## §11: synthetic candidate sets

Benchmark logs contain 16 signed synthetic records with the same issuer,
policy, and run-length bucket. This is a small, weak **structural** candidate
set. The recorded fixture seed exposes their witnesses, so these runs are
neither an anonymity measurement nor a demonstration of witness privacy.
Proof randomness comes from Nova's fresh OS randomness. The presentation API
also resamples accumulator blinding internally for every proof. Production
callers must use fresh receipt secrets and their own issuer key custody.

## Verification boundary and benchmark accounting

`proofs::verify` checks the compressed proof against verifier-owned public
bindings and the exact halted output. `verify_authenticated` additionally
uses zkar-core's strict Ed25519 verifier for the pinned log head, framing its
root and size from those same expected values. `sealed::verify_sealed_receipt`
adds strict wire validation, proof decoding, pinned-key digest comparison,
expected issuer/policy/scope checks, and atomic replay storage. `zkar verify`
uses that complete boundary; `zkar check` still reports schema-only or partial
success and does not verify the proof.

Benchmark verifier times cover the SNARK checks and output comparison;
they exclude Ed25519 log-head verification, proof decoding, and replay-set
storage. Fixture construction, native trace preparation, and constraint
accounting occur outside setup/prover timers. Peak RSS covers the entire
fresh measurement process, including those operations. Direct baselines
omit padding; per-entry setup reuses keys for START+first STEP, STEP, and
FINAL, producing T+1 proofs and charging key generation only on first use.
The JSON `folds` field records the fixture's Nova comparison bucket for all
three systems; direct baselines do not execute folds.
Per-entry proofs are produced, encoded, verified, and released one at a time;
their memory result describes that streaming schedule. Proof sizes exclude
verification keys, public-input transport, and any multi-proof container.

Verification keys must be generated from or pinned to the receipt circuit.
Accepting a prover-supplied key would allow proofs of an unrelated circuit.
The benchmarks generate their own keys from the source relation.

## §9.1: uniform Nova instead of SuperNova

The requested nova-snark 0.76.0 implementation supports uniform Nova. The
primary engine is VestaEngine and the secondary engine is PallasEngine. The
primary scalar field is the Pallas base field. A single step circuit contains
start, inventory-step, and final branches. Every fold pays for every branch,
including the issuer signature and log membership. This differs from the
paper's cost model. Standalone branch counts are a SuperNova-style cost
**estimate**, not measurements of a SuperNova implementation.

As specified in §9.1, the final transition binds the starting task metadata
through the signed transcript; it does not carry a separate task-binding
slot in the accumulator. This relies on the trusted issuer computing the
signed transcript from `S.task_binding` faithfully. The issuance helper does
so; the proof does not establish honest behavior by a malicious issuer.

Nova's own 0.76.0 README cites Nguyen, Boneh and Setty, *Revisiting the Nova
Proof System on a Cycle of Curves* (2023/969), for its cycle instantiation.
Using uniform Nova avoids claiming a proof of a SuperNova/cycle composition.
We have not independently audited the correspondence between the dependency
implementation and that proof.

## §9.2: compression source inspection

In nova-snark 0.76.0, `src/nova/mod.rs`, `CompressedSNARK::prove`
(lines 795–912 in the published crate) is documented as providing zero
knowledge. Beyond that comment, it actually calls
`sample_random_instance_witness` on both primary and secondary R1CS shapes
and folds the results with `NIFSRelaxed::prove` before Spartan compression.
`src/r1cs/mod.rs`, lines 758–812, samples field values with `OsRng` and
computes the error vector `E = AZ ∘ BZ - u CZ`, yielding a satisfying
**relaxed** R1CS instance. The README attributes this hiding construction to
HyperNova. Thus the required random satisfying-instance fold is performed
inside compression; it is not an additional receipt transition or padding
fold. The chosen Spartan uses transparent IPA on both curves.

This source inspection supports use of the library's documented zero
knowledge construction. It is not an independent cryptographic security
proof. Only the compressed proof is intended for presentation; recursive
proofs and witnesses are not presentation artifacts.

## Baseline confidentiality and linking

The direct Spartan baselines use `spartan::direct::DirectSNARK` with the same
relation gadgets and IPA engine. This direct API does not perform the random
satisfying-instance fold used by `CompressedSNARK`. We do not claim these
baseline proofs provide zero knowledge. Per-entry proofs are not a securely
linked receipt construction, as allowed by the benchmark brief; their costs
understate a secure composed construction.

## Build and serialization

The prover and CLI require Rust 1.89 or newer for standard-library file
locking; nova-snark 0.76.0 and halo2_poseidon 0.2.0 require at least 1.88.
Proof byte counts use bincode 2.0.1's serde encoder with `config::legacy()`,
the configuration used by Nova's examples, without the optional zlib layer.
New direct dependencies are pinned exactly; Cargo.lock pins the full graph.

## Internal security review, 8 Nov 2026: changes and residual dependencies

An internal security review read the circuit twice and attacked it with 17
adversarial constraint-system tests (`tests/adversarial_witness.rs`). It found
no soundness break. It is not an independent audit. Changes made from its
findings:

- **Pinned verification keys.** `proofs::verify` and `verify_authenticated`
  now take a `PinnedVerifierKey`. It is built once, at key load, and checks
  SHA-256 over `"SAR-ZK-vk-digest-v0.4\0"` and the bincode encoding of the
  key against a digest the verifier pinned in advance. A key shipped with a
  proof could belong to any circuit that outputs the expected final state.
  The check runs outside the benchmark's verifier timer. A test rejects a
  wrong digest.

Residual dependencies, stated so a reader can audit them:

- **Complete ECC gadgets.** The Schnorr verifier relies on nova-snark 0.76.0's
  `AllocatedPoint::add` (`src/gadgets/ecc.rs:142`), `double` (`:392`) and
  `conditionally_select` (`:585`) being complete, including identity and
  equal-point inputs. It never calls `scalar_mul` (`:496`) or the incomplete
  variants (`:729`, `:791`). Edge-scalar tests (0, 1, `q-1`, `s+q`) are the
  regression canaries.
- **The on-curve constraint is load-bearing.** With an off-curve key or `R`,
  the group equation can hold on the arithmetic fallback; only the on-curve
  constraint rejects it. Keep its regression tests.
- **Inactive branches carry real witnesses.** On every fold, each inactive
  branch runs on a fallback input state (spec §9.1). The honest prover pairs
  that state with the branch's real witness. This is sound, but
  recursive (uncompressed) proofs reveal witnesses and must never leave the
  prover. Only compressed proofs are presentation artifacts.
- **Cost, not soundness.** The policy opening is re-checked and some values
  are range-checked again on every fold. Removing the repeats would lower the
  uniform cost; the published numbers keep them.
- **Per-entry baseline.** Its verifier receives the prover's trace states and
  does not chain them. That makes it cheaper than a sound linked construction,
  so it favours the baseline.


## Wire and verifier hardening

The envelope is exactly `{ profile, public_input, proof, fold_count, algorithm }`.
`fold_count` is a canonical decimal string and a power of two in `[4, 2^20]`.
The algorithm object contains exactly `arithmetization`, `curve`,
`proof_encoding`, and `vk_digest`. Its implemented values are
`r1cs-nova-uniform`, `pasta`, and
`nova-snark-0.76.0/bincode-2.0.1-legacy`. The schema reserves
`r1cs-supernova`, but this verifier rejects it. The digest is 64 lowercase hex
characters identifying the verifier's own pinned key; no key is loaded from
the receipt. Duplicate, missing, unknown, and noncanonical members are rejected.

Full verification revalidates directly constructed Rust receipts as well as
parsed JSON. It checks the pinned key/digest, decodes canonical field values
without modular reduction, authenticates the head built from the same root
and tree size used by Nova, checks the compressed proof and verifier-selected
issuer/policy/scope, then calls the replay set. The proof is canonical unpadded
base64url followed by bincode 2 legacy decoding, capped at 64 KiB decoded bytes,
with trailing bytes rejected. Receipt JSON is bounded at 128 KiB in the CLI;
64 KiB of proof alone expands to 87,382 base64url characters.

Replay storage implements one atomic `check_and_insert(scope, nullifier)`.
The memory implementation uses a mutex; the file implementation locks
exclusively around lookup and append and fails closed on storage errors.
A successful repeated pair yields `ReplaySuspected`; CLI exit 4 is distinct
from success (0), invalid receipt (1), partial (2), schema only (3), and usage
(64). Replay storage must remain under verifier control and survive restarts.
Fresh blinding does not change a receipt's scoped nullifier. `Fixture::present`
samples blinding from `OsRng` inside every proving call, reblinds every
accumulator opening, and produces a new compressed proof; it has no caller-rho
parameter. Its prover-side `rho` accessor supports presentation audits.

Native padding preparation computes the same transcript-step Poseidon hash as a
real entry and discards the result. Padding therefore does not skip that hash;
the selected transcript, index, and payment count remain unchanged, as in the
circuit.

### Reproducible verification keys

Source inspection of nova-snark 0.76.0 shows that `PublicParams::setup`
synthesizes the primary and secondary shapes, then derives their commitment
keys through `R1CSShape::commitment_key`. The selected non-preprocessed
`spartan::snark::RelaxedR1CSSNARK` inherits the trait's default zero `ck_floor`
hint; key sizing uses `max(num_cons, num_vars, 0)`. Pedersen setup derives generators with
`GE::from_label(b"ck", n.next_power_of_two() + 1)`; IPA uses the label `b"ipa"`.
These paths are deterministic for a fixed circuit shape. The regression test
runs setup and compression-key generation twice and compares `vk_digest`.
A verifier can regenerate the key from this pinned source/dependency stack
and compare its digest with the independently pinned release digest. This
claim does not extend to changed circuit shapes or dependency versions.
