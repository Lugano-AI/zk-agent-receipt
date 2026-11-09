# SAR-ZK zkVM baseline results

Updated: `2026-11-09T14:30:07+00:00`

This report contains only completed measurements. A skipped or timed-out row is not a performance result; inspect its raw logs and recorded rationale in `results.json`.

## Method

- Seed: `5341522d5a4b2d76302e34622d666978747572652d736565642d303030312121`
- Requested T values: 10, 100, 1000
- CPU selection: `risc0-zkvm = =3.0.6` with `default-features = false`, `std+prove`, no CUDA; fresh processes set `RISC0_PROVER=local`, `RISC0_EXECUTOR=local`, and `RISC0_DEV_MODE=0`. `RISC0_BACKEND` is intentionally unset because v3.0.6 has no such selector.
- Proof-generation timing excludes fixture creation, native relation checks, receipt serialization, receipt verification, and receipt-artifact I/O. Process peak RSS covers the full process lifetime. Larger-T cutoff estimates anchor to the nearest completed smaller same-kind proof configuration, not blindly to T=10.
- Each proof artifact is bincode 1.3 bytes plus an expected-journal sidecar, written after timing and independently re-verifiable with `baseline-host verify --receipt <path>`.

Observed host runtime: available parallelism `18`, Rayon pool width after timing `18`, `RAYON_NUM_THREADS` `None`.

## Standalone execution preflight

| T | status | successful samples | execution median ms | total cycles | user cycles | segments | peak RSS bytes |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | complete | 3 | 208.6 | 20,971,520 | 19,739,301 | 20 | 47,710,208 |
| 100 | complete | 3 | 744.9 | 82,837,504 | 78,327,938 | 79 | 48,463,872 |
| 1000 | complete | 3 | 6,830.9 | 749,207,552 | 712,519,579 | 715 | 51,249,152 |

## Proofs

| receipt | T | status | successful samples | proof-generation median ms | verify median ms | receipt bytes | total cycles | peak RSS bytes |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| composite | 10 | pending | 0 | — | — | — | — | — |
| composite | 100 | pending | 0 | — | — | — | — | — |
| composite | 1000 | pending | 0 | — | — | — | — | — |
| succinct | 10 | pending | 0 | — | — | — | — | — |
| succinct | 100 | pending | 0 | — | — | — | — | — |
| succinct | 1000 | pending | 0 | — | — | — | — | — |

## Environment

Filtered hardware and tool-version evidence is stored verbatim in `results.json`; serial numbers and platform UUIDs are intentionally not collected.
