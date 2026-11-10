# RISC Zero SAR-ZK baseline

This independent Cargo workspace implements the SAR-ZK v0.4b relation from
[`spec/SAR-ZK.md`](../../spec/SAR-ZK.md) and the `zkar-circuit` reference,
including the Pallas Schnorr check omitted by that reference. It does not
depend on or modify the [`zk-agent-receipt`](../zk-agent-receipt) workspace.

`relation/` contains the shared verifier, deterministic fixture generator,
and tests. `methods/guest/src/main.rs` reads the witness, requires that
verifier to succeed, and commits its seven-field journal. The separate
`check` guest exercises arithmetic boundary cases; it cannot be selected
through the baseline guest's input. `host/` executes, proves, verifies, and
captures process resource usage. `scripts/run_benchmarks.py` runs each sample
in a fresh process and writes durable raw records, receipts, `results.json`,
and `results.md`.

| Required check | Implementation |
| --- | --- |
| 1. Poseidon | `halo2_poseidon = 0.2.0` P128Pow5T3 constants, 8 full/56 partial rounds; zero-state rate-2 sponge absorbs big-endian ASCII tag and arity first, then zero-padded input pairs. This is not Orchard's differently framed `Hash` API. |
| 2. Policy | Recompute policy commitment; depth-16 tool paths; enforce egress permission and payment count; reject unknown/padding kinds. Digests are two fixed 128-bit big-endian limbs; bounds/indices are typed or explicitly checked. |
| 3. Transcript | Start with `H_transcript(S.task_binding)`, hash every real entry with its one-based index, require final equality and `1 <= step_count = T < 2^32`. |
| 4. Issuer | Canonical Pallas coordinates, non-identity/on-curve PK and R, canonical scalar `s < q`, fixed generator `(p-1,2)`, exact five-element challenge and `sG = R + cPK`; check the supplied issuer commitment. |
| 5. Log | `H_leaf(H_statement(S))`, exactly 32 siblings, `1 <= tree_size <= 2147483647`, and `leaf_index < tree_size`. |
| 6. Nullifier | Check `H_nk(nk,r)` against S and `H_nullifier(nk,scope)` against the expected public nullifier. |
| 7. Journal | Exactly profile tag, issuer commitment, log root, tree size, policy commitment, scope, nullifier, in that order. No witness or fixture metadata is committed. |

Binary field wires are canonical 32-byte little-endian encodings, rejected
at or above their modulus. Digest limbs and domain tags retain the spec's
big-endian integer meaning. This internal transport is not an implementation
of the profile's decimal-string JSON wire format. The journal uses RISC Zero
Serde. Receipt sizes use the entire `Receipt` encoded by `bincode::serialize`
from bincode 1.3.3: little-endian, fixed-width integer encoding.

The selected guest feature is `risc0-accelerated`: Poseidon multiplication
uses `risc0-bigint2 = 1.4.14`'s checked `modmul_256` with the Pallas modulus.
Canonical limbs are converted at permutation boundaries; the relation and
sponge framing are shared with the portable native implementation. Constants
are converted once per verification. Domain/arity prefix states and exact
ordered Merkle-node hashes are cached within an invocation. Repeated identical
tool paths can also reuse a completed check. These caches do not bypass a
membership assertion or assume anything about the supplied witness.

Schnorr point parsing and every validity check (on-curve, non-identity,
`s < q`, canonical encodings) stay with the portable `pasta_curves = 0.6.1`
implementation, but in the selected guest the two verifier scalar
multiplications (`generator * s`, `public_key * challenge`) and the final
`R + cPK` addition now run over `risc0-bigint2`'s generic affine
short-Weierstrass precompiles configured for Pallas (`a = 0`, `b = 5`);
see `relation/src/pallas_accelerated.rs`. The bigint2 point operations
assert canonical coordinates against a dishonest host, and the guest's
`check-arithmetic` self-test compares this curve layer against portable
Pasta on boundary scalars and the `P + P` addition edge before use.
The optional, mutually exclusive `risc0-legacy-mul` feature was implemented
and measured too, using `sys_bigint(OP_MULTIPLY)` with a canonical-output
check. At T=10 it used 35,651,584 total cycles, versus 33,816,576 with bigint2,
so it was not selected. The binaries and raw records of those comparison runs
are not in this repository.

Fixtures use ChaCha20 with seed
`5341522d5a4b2d76302e34622d666978747572652d736565642d303030312121`.
Entry kinds repeat tool/file/payment/egress; every tool digest is distinct.
At T=10/100/1000, tool counts are 3/25/250 and payment counts are 2/25/250.
Egress is allowed and the payment bound is the actual count plus one.
Allowlist digests are sorted and duplicate-free. The sparse depth-32 log has
13/103/1003 populated leaves respectively, with the tested statement at a
seeded index; filler leaves are hashes of syntactically valid one-entry
statements. Log size is not a measured candidate set or an anonymity claim.
The seed and metadata are benchmark artifacts, not production randomness.

The guest proves the requested semantic relation using RISC Zero rather than
IVC, so it does not compute folding accumulator commitments or padding folds.
It does not perform the outer Ed25519 log-head check, pin application policy
or issuer keys, manage replay state, or implement the complete SAR-ZK wire
protocol. The benchmark host checks the receipt against its expected journal.
This is not a security audit, a proof of protocol composition, or a privacy
analysis of observable workload/segment information. A folding comparison
must use a comparable inventory mix and account for shared Merkle work.
The supplied SAR-ZK draft has no published profile test vectors. Tests check
the permutation against `halo2_poseidon`, inspect the specified framing, and
compare native and guest outputs; they do not establish interoperability
against a published SAR-ZK vector suite.

This workspace builds a RISC Zero v3.0.6 guest and an Apple Silicon native
host for the SAR-ZK baseline. The benchmark profile is intentionally CPU-only:

```sh
export PATH="$HOME/.risc0/bin:$PATH"
cargo +risc0 build --release --target aarch64-apple-darwin -p baseline-host
cargo +risc0 test --target aarch64-apple-darwin -p relation --lib --test requirements
target/aarch64-apple-darwin/release/baseline-host check-arithmetic
python3 scripts/run_benchmarks.py --execute-only --results-dir bench-results/execute-review
```

The scoped native-test command runs the unit/adversarial tests. The
unscoped command also attempts doc-tests and fails because the installed
RISC Zero toolchain has no `rustdoc`.
Negative cases are `wrong-tool`, `wrong-transcript`, `wrong-signature`, and
`wrong-nullifier`, for example:

```sh
target/aarch64-apple-darwin/release/baseline-host negative --t 10 --case wrong-tool
target/aarch64-apple-darwin/release/baseline-host verify --receipt bench-results/serial-proof/receipts/composite-t10.receipt
```

Only `negative` enables dev mode, and it first requires a successful positive
control in the same process. `execute`, `prove`, and artifact verification
reject enabled dev mode. Proof samples use the local CPU prover and check the
actual receipt variant: default composite or `ProverOpts::succinct()`.
Each sample verifies its receipt and compares the journal with native results.
The runner binds samples to a binary hash, lockfile hash, and guest image ID.

### Serial proof run

Build the native host as above. On a quiet machine, set `N` to the desired
entry count and run **one command at a time**:

```sh
export PATH="$HOME/.risc0/bin:$PATH"
export RISC0_DEV_MODE=0 RISC0_PROVER=local RISC0_EXECUTOR=local
unset RISC0_BACKEND
N=10
mkdir -p bench-results/serial-proof/receipts
target/aarch64-apple-darwin/release/baseline-host prove --t "$N" --receipt-kind composite --receipt-out "bench-results/serial-proof/receipts/composite-t${N}.receipt"
target/aarch64-apple-darwin/release/baseline-host prove --t "$N" --receipt-kind succinct --receipt-out "bench-results/serial-proof/receipts/succinct-t${N}.receipt"
```

Repeat with `N=100` or `N=1000` only as intended for that serial run. The
harness rejects enabled dev mode, selects the local prover, requests the
chosen SDK receipt kind, checks the returned variant, verifies the receipt,
and compares its journal to native verification. The raw records of the
measured run are in `bench-results/2026-11-09-quiet/raw/`: three runs per
receipt kind at T=10 and one run per receipt kind at T=100. One composite run
at T=1000 is in `bench-results/2026-11-10-t1000/`, with its load log; other
programs used the machine during that run. Succinct T=1000 was not proved. The
receipt files are not in this repository because of their size (about 0.2 to
201 MB each); the `receipt_path` fields in the raw records name where they
were written. For the full budgeted serial runner, use an
explicit fresh output directory:

```sh
RISC0_DEV_MODE=0 python3 scripts/run_benchmarks.py --results-dir bench-results/serial-proof-run
```

Reported proof time includes guest execution and all work inside
`prove_with_opts`; it excludes fixture generation, native pre/post checks,
receipt verification, serialization, and artifact I/O. Verification time is
measured after proving in the same fresh process, and can benefit from warm
caches. Separate artifact verification provides an additional correctness
check. Peak RSS is macOS `getrusage(RUSAGE_SELF).ru_maxrss` in bytes for the
whole process, including setup and serialization. Rayon pool width is queried
after timing. Total cycles are RISC Zero's actual session counter and include
paging/reserved capacity; user cycles and segment counts are recorded too.

Normally the runner takes three samples per size and receipt type. It stops
sampling after an actual run exceeds 30 minutes, enforces a cumulative
90-minute configuration budget, and skips a configuration when a measured
smaller same-kind proof predicts a single run above that limit. Estimates are
recorded as estimates, never as measurements. Raw logs survive failure or
timeout. `--resume` checks artifact identity before continuing.

The `risc0` toolchain itself must be the native Apple Silicon toolchain
(`rustc +risc0 -Vv` currently reports `host: aarch64-apple-darwin`). Passing
`--target aarch64-apple-darwin` to the default x86_64 Cargo alone is not
sufficient: it still runs `methods`' build script as x86_64, which RISC Zero
v3.0.6 rejects as an unsupported macOS build-script architecture.

The host enables `risc0-zkvm`'s `prove` feature without `cuda`. In v3.0.6,
the segment and recursion prover selection falls through to their CPU HALs;
`RISC0_PROVER=cpu` is not a supported RISC Zero value.

## macOS CPU-only build note

`risc0-zkp` v3.0.5 requires an embedded Metal asset on macOS when `prove` is
compiled, despite the v3.0.6 CPU path not using it. The benchmark machine also
lacks the Xcode Metal Toolchain. The workspace therefore vendors only `risc0-sys`
v1.5.0 and sets `RISC0_BASELINE_CPU_ONLY=1` in `.cargo/config.toml`. Its
build script writes an empty, compile-time-only Metal payload; it does not
modify the zkVM, prover, or relation cryptography.

That artifact makes Metal proving intentionally unsupported for this workspace.
Do not unset the flag or select a Metal prover for a benchmark run. CPU circuit
kernels are still built normally; this is not `RISC0_SKIP_BUILD_KERNELS`.
