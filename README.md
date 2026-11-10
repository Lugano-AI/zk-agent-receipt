# Sealed Receipts

> A draft for public comment, by Lugano Labs. Nobody outside Lugano Labs has audited this work. Do not use it to protect real data.

When an AI agent finishes a task, a signed record of the task can exist. With a plain signed record, to prove a fact about it, you must show the whole record. Sealed Receipts let the holder prove that the record follows a policy and keep the record private.

This repository holds the paper, the profile, a reference prover in Rust and the measurements behind the paper. It builds on [Signed Agent Receipt v0.2](https://github.com/Lugano-AI/signed-agent-receipt).

## What is here

| Path | Contents |
| --- | --- |
| [`paper/draft.md`](paper/draft.md) | The paper, draft v0.5. It gives the design, the security argument, the experiment and the limits. |
| [`spec/SAR-ZK.md`](spec/SAR-ZK.md) | The SAR-ZK v0.4-draft profile. This is the normative text. |
| [`code/zk-agent-receipt`](code/zk-agent-receipt) | The reference prover and verifier for profile b, in Rust, with its tests and benchmark results. |
| [`code/zkvm-baseline`](code/zkvm-baseline) | The same relation in RISC Zero 3.0.6, for comparison, with its results. |

## What a sealed receipt proves

The holder convinces a verifier of three things and does not show the record:

- A trusted issuer signed the record.
- The record is in a signed log.
- The record meets a policy that the verifier selects: only approved tools, nothing sent outside, and no more than a set number of payments.

A sealed receipt proves facts about the record as the issuer wrote it. It does not prove that the agent ran as the record says, or that no data left the system.

## What we measured

We ran all tests on one Apple M5 Max (18 cores, 128 GB), on the CPU only. Our prover's figures are medians of three runs. So is the RISC Zero figure at 10 steps.

| Task steps | Our prover | RISC Zero 3.0.6, composite receipt | RISC Zero time ÷ our time |
| ---: | ---: | ---: | ---: |
| 10 | 4.877 s | 795.330 s | 163 |
| 100 | 15.298 s | 3,311.618 s (one run) | 216 |
| 1,000 | 94.926 s | 29,316.134 s (one run, on a machine in use) | 308 |

At 1,000 steps, our proof is 11,784 bytes and the check takes about 63.9 ms. The proof size stayed the same at 10, 100 and 1,000 steps, and the median check time stayed between 59.9 and 64.3 ms. Single runs took from 58.0 to 186.2 ms.

We ran the 1,000-step RISC Zero case once. It took about 8.1 hours, and other programs used the computer during the run. That slows RISC Zero down, so a quiet machine would give a smaller ratio. We do not know by how much. The load log is in the results files, and Section 9 of the paper gives the details.

### Where the comparison does not favour us

- RISC Zero's succinct receipt checks in about 9 ms at the two sizes where we measured it, 10 and 100 steps. Ours takes about 64 ms.
- RISC Zero proves any program. Our prover proves one fixed relation.
- The Apple GPU path is disabled in the RISC Zero 3.0.6 source, and we did not test a CUDA GPU. A GPU should make RISC Zero faster. We cannot say by how much.
- The RISC Zero runs at 100 and 1,000 steps are one run each, not medians. The 1,000-step run shared the CPU with other programs, which favours us.
- Section 9 of the paper lists the cases where our other two baselines win: one proof is smaller, and one uses less memory.

### The three hypotheses

We wrote the hypotheses before we measured. This is our own account; we did not register them with a third party.

- **H1: the measurements support it.** Proof size and check time stay flat from 10 to 1,000 steps.
- **H2: the measurements support it, with a condition.** Our prover is more than 10 times faster than the zkVM on the same relation. The zkVM guest is stricter on one point, the task binding. The two provers ran test records of the same length but not the same content; Section 9.2 of the paper lists the differences. The 1,000-step RISC Zero figure is one run on a machine in use, and both systems ran on the CPU only.
- **H3: we cannot test it as written.** The prover uses uniform Nova, which has no separate final circuit. The paper reports the nearest measured quantity and does not rewrite the hypothesis.

## Build and test

You need Rust 1.89 or later. On Apple Silicon, select the arm64 target:

```sh
cd code/zk-agent-receipt
cargo test --target aarch64-apple-darwin -j 8 --workspace
```

The suite has 142 tests. Six more run only in release mode; the command for them is in [`code/zk-agent-receipt/README.md`](code/zk-agent-receipt/README.md). That file also shows how to make keys, check a receipt and run the benchmark.

The RISC Zero baseline needs the RISC Zero toolchain. See [`code/zkvm-baseline/README.md`](code/zkvm-baseline/README.md).

## The results files

- Our prover: [`code/zk-agent-receipt/bench-results/2026-11-09-quiet/`](code/zk-agent-receipt/bench-results/2026-11-09-quiet/) has `results.md`, `results.json`, the run log and the raw record of each run.
- RISC Zero: [`code/zkvm-baseline/bench-results/2026-11-09-quiet/raw/`](code/zkvm-baseline/bench-results/2026-11-09-quiet/raw/) has the raw record of each proof run. [`2026-11-09-fairness/`](code/zkvm-baseline/bench-results/2026-11-09-fairness/) records two changes that made the baseline faster before we measured it, with the cycle counts before and after. [`2026-11-10-t1000/`](code/zkvm-baseline/bench-results/2026-11-10-t1000/) has the raw record, the run details and the load log of the 1,000-step run.

We changed four things before we published these files:

- We made the file paths in the RISC Zero records relative. No measured value changed.
- We left out the RISC Zero receipt files. They range from 0.2 to 201 MB. The raw records keep their sizes and timings.
- We removed the names of the other programs from the load log of the 1,000-step run. The CPU figures are unchanged.
- After the measured runs, we edited comments, the documents and the name of one test file. We changed no prover logic and no relation logic.

After the first release, an internal security review led to small hardening changes. The verifier now turns a library panic on a malformed proof into a rejection. It checks the expected policy, scope and issuer before it checks the proof. The prover refuses a run that is too long for the receipt format. The replay file is flushed to disk. The command line returns 64 for more kinds of bad input. These changes add a few cheap checks to the code that the benchmarks time. We did not run the benchmarks again.

## Limits

- This is draft research code. It has had an internal security review. It has not had an independent audit.
- Profile a (an Ed25519 issuer signature checked inside the circuit) is not built.
- The fixtures are synthetic. Their seeds are public. Never use them for a real receipt.
- The benchmarks measure time and size. They do not test privacy.
- Section 10 of the paper gives the full list.

## Comments

We want to know what is wrong. Open an issue, or write to contact@lugano.ai.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Lugano AI Holdings LLC.
