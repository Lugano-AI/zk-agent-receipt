# RISC Zero at 1,000 entries: a quiet attempt that gave no time

On 10 and 11 November 2026 we tried to repeat the 1,000-entry composite proof on a quiet machine. We used the same binary, seed and settings as the run in `../2026-11-10-t1000`, and the binary hash in `run-meta.txt` matches it.

The run started at 22:14 local time on 10 November, after other programs had used under 150% of one core for ten minutes in a row (`gate-log.txt`). After 7 hours 13 minutes, the prover stopped with this error (`raw/prove-composite-t1000-r2.stderr.log`):

    baseline-host error: proving baseline guest: verify segment: verification indicates proof is invalid

The error says that a segment proof failed RISC Zero's own check. The run wrote no receipt and no time. We don't know the cause, and one failed run can't tell a prover fault from a hardware error. We haven't repeated the attempt.

Over 86 samples after launch, the prover held a mean of 1,637% of the CPU out of 1,800%. Other programs used 9% to 236% of one core, 51% on average (`load-samples.txt`; we removed the program names).
