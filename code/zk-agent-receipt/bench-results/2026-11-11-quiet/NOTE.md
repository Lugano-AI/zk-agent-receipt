# Benchmark run, 11 November 2026

This run timed the published v0.5 code. We built the binary on 10 November from the tagged code (tag v0.5, commit 648975a). The working tree was at commit 0d55658, which changes only the paper, so `run-meta.txt` names that commit. On 11 November we checked that no source file was newer than the binary, and that the working tree's code matched tag v0.5 (`git diff --quiet 648975a -- .` in `code/zk-agent-receipt`).

- **Machine:** one Apple M5 Max with 18 CPU cores and 128 GB of memory, CPU only.
- **Command:** `zkar-bench --t 10,100,1000 --reps 3`. Each configuration ran three times, each in a fresh process.
- **Start rule:** the run waited until all other programs together used under 150% of one core for ten minutes in a row. `gate-log.txt` records each minute. The rule was met at 13:37 UTC. The run started at 13:38 and ended at 15:02 UTC (`run-meta.txt`).
- **Load:** `load-samples.txt` has one sample every five minutes. Across 17 samples, other programs used 21% to 161% of one core, 75% on average. We removed the names of those programs. We also removed the sampler's reading of the prover's own CPU use. It watched the parent process, which only starts the workers, so it read 0% throughout.
- **Results:** `results.md` has the medians, `results.json` has every run, and `raw/` has each worker's output.
