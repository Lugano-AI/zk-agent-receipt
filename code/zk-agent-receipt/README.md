# zk-agent-receipt

Reference code for **Sealed Agent Receipts (SAR-ZK v0.4-draft)**: zero-knowledge
policy checks for AI agent task records. It builds on
[Signed Agent Receipt v0.2](https://github.com/Lugano-AI/signed-agent-receipt).

**Status: draft, not audited. An experimental profile-b prover is implemented.**
The native Rust API proves and verifies the relation using uniform Nova and
transparent IPA/Spartan compression. `zkar verify` checks the transported proof,
pinned verification key, signed log head, verifier-selected commitments, and
an atomic replay set. `zkar check` retains its schema/signature-only behavior.

## Build and test

The prover and CLI require Rust 1.89 or later (including standard-library file
locking); this workspace uses Rust 1.94.0. On Apple Silicon, select the arm64 target explicitly:

```sh
cargo test --target aarch64-apple-darwin -j 8 --workspace
RAYON_NUM_THREADS=8 cargo test --release --target aarch64-apple-darwin -j 8 -p zkar-prover -p zkar-cli -- --ignored --test-threads=1 --nocapture
cargo run --target aarch64-apple-darwin -j 8 -p zkar-cli -- fixtures out
cargo run --target aarch64-apple-darwin -j 8 -p zkar-cli -- check out/sealed-receipt-0.json --trust out/log-trust.json
```

The last command prints `LOG HEAD SIGNATURE OK; PROOF NOT CHECKED` and exits
with code 2.

The first command runs the fast tests. The repository's CI runs only that
command and the lint. The second command runs the seven tests that make and
check real proofs. They need a release build and several minutes, so run them
yourself before you rely on a change to the prover.

## What the code does today

- **`zkar-core`**
  - Parses sealed receipts strictly: unknown, missing and duplicate members are
    rejected (including duplicates hidden by JSON escapes), and so are JSON
    number tokens.
  - Checks lexical forms: `ID`, `DIGEST`, `DECIMAL`, canonical unpadded
    base64url, and field elements below the Pallas modulus.
  - Builds the length-framed log-head bytes (spec §7.1).
  - Verifies the head's Ed25519 signature strictly, rejecting small-order and
    non-canonical keys.
  - Holds the policy type (spec §6).
- **`zkar-circuit`** states the SAR-ZK v0.4 relation in plain Rust, over an
  abstract field and hash: the transcript, the policy checks, the fixed-depth
  log and allowlist trees, the nullifier-key commitment and the scoped
  nullifier. Its tests use a stand-in hash that is *not* Poseidon and not
  secure. The issuer signature and the folding state machine are not mirrored.
- **`zkar-cli`**
  - The binary is `zkar`. `check` validates a receipt. With `--trust`, it also verifies the log-head
    signature against a pinned key.
  - `verify` performs the full profile-b check and records successful nullifiers.
  - `keygen --out <dir>` writes `uniform-vk.bin` and `uniform-vk.sha256`.
  - `fixtures` writes synthetic schema/signature test data with an empty proof.
  - `digest` prints a file's SHA-256 in v0.2 form.
- **`zkar-prover`** implements exact Orchard Poseidon, native and in-circuit
  Pallas Schnorr, the uniform start/step/final relation, synthetic issuance,
  compressed Nova verification, and direct Spartan baselines. Its sealed-receipt
  verifier checks the pinned Ed25519 log head and atomically records replays.
  The presentation API samples fresh accumulator blinding internally per proof. See
  [SPEC-NOTES.md](crates/zkar-prover/SPEC-NOTES.md) for security boundaries,
  source inspection, and differences from the paper's cost model.
- **`zkar-bench`** runs each system/T/repetition in a fresh process and records
  raw results, medians, process RSS, exact dependency versions, and child logs.

```sh
cargo run --release --target aarch64-apple-darwin -p zkar-bench -- --t 10,100,1000 --reps 3 --out bench-results/my-run
```

The measured results in this repository are in
[`bench-results/2026-11-09-quiet/`](bench-results/2026-11-09-quiet/).

Uniform Nova pays all three branches on every fold. Standalone branch counts
estimate a SuperNova-style cost; no SuperNova implementation is measured.
Direct baseline proofs carry no zero-knowledge guarantee here, and the
per-entry baseline is not a securely composed receipt. Published fixture seeds
expose synthetic witnesses and must never be used for real receipts.

Exit codes for receipt checking:

- 0: full verification passed (`verify` only);
- 1: the check failed;
- 2: the schema and the log head signature passed, but the proof was NOT verified;
- 3: the schema passed, and nothing cryptographic was checked;
- 4: a valid receipt repeats a stored scope/nullifier pair (`ReplaySuspected`);
- 64: bad command line (an unknown command, a missing or extra argument, or an
  argument that is not valid UTF-8).

Receipt/trust JSON inputs are limited to 128 KiB: a 64 KiB compressed proof
requires 87,382 unpadded base64url characters before JSON metadata. Decoded
proofs are capped at 64 KiB; bincode trailing bytes are rejected. Verification
key files are capped at 128 MiB because they contain the full constraint shape.

A test feeds both decoders 1,537 malformed byte streams of up to 64 KiB each.
No decoder panicked. The proof decoder held at most 1,114,263 bytes at one
time, and the key decoder at most 2,105,349 bytes. The test fails above 4 MiB
and 8 MiB. Malformed key files above 64 KiB are not tested.

One `zkar verify` run on a 10-entry record took about 6.5 s (median of 10
runs, one new process each, on a machine in use). Loading the verification key
takes about 6.2 s of that: the file is 64.6 MB, and decoding it takes about
5.95 s. A verifier that stays running loads the key once.

The proof library can panic on a proof whose inner vectors have the wrong
length. The verifier catches that panic and rejects the receipt. Do not build
it with `panic = "abort"`: the process would stop instead.

Full verification requires independently selected expected commitments and a
persistent replay file. Pin the digest through a trusted channel; never accept
a key or expected commitments merely because a receipt supplied them.

```sh
cargo run --release --target aarch64-apple-darwin -j 8 -p zkar-cli -- keygen --out keys
cargo run --release --target aarch64-apple-darwin -j 8 -p zkar-cli -- verify receipt.json \
  --vk keys/uniform-vk.bin --vk-digest <pinned-64-lowercase-hex> \
  --trust log-trust.json --expected-policy <decimal> \
  --expected-scope <decimal> --expected-issuer <decimal> \
  --replay-file replay.log
```

The append-only replay file is locked exclusively across lookup and durable
insertion. Lock, read, corruption, and write failures reject verification. Keep
the file in verifier-controlled storage; deleting it discards replay history.
If the file disappears while the verifier runs, the next check fails. Each
check reads the whole file, so the cost grows with the number of stored pairs.
A busy verifier needs an indexed store.
Two presentations of one issued receipt retain the same scoped nullifier even
though their accumulator blinding and compressed proof randomness are fresh.

The wire envelope is exactly `{profile, public_input, proof, fold_count,
algorithm}`. `fold_count` is a decimal string, a power of two from 4 through
2^20. `algorithm` contains `arithmetization`, `curve`, `proof_encoding`, and
`vk_digest`. The implementation accepts `r1cs-nova-uniform`, `pasta`, and
`nova-snark-0.76.0/bincode-2.0.1-legacy`; `r1cs-supernova` is reserved and
rejected by full verification. `vk_digest` is 64 lowercase hex characters
identifying the verifier's pinned key, never a key-loading instruction.

The trust file names its log, and `check` refuses a key pinned for a different
log:

```json
{ "profile": "sar-zk-log-trust-v0.4", "log_id": "log.1", "ed25519_public_key_hex": "<64 lowercase hex>" }
```

## Not built yet

- Non-uniform SuperNova folding.
- In-circuit Ed25519 issuer signatures (profile a).
- An external cryptographic audit, and test vectors that a second implementation has confirmed. The vectors in `spec/vectors` come from this code only.

The RISC Zero baseline is a separate workspace: [`../zkvm-baseline`](../zkvm-baseline).

Fixtures are synthetic. They are never real task records.

License: Apache-2.0.
