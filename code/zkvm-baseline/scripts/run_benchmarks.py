#!/usr/bin/env python3
"""Run the SAR-ZK zkVM benchmark with durable, resumable evidence.

The runner deliberately performs standalone execution at every requested T
before it starts any proof. It uses observed execution cycles and the nearest
completed smaller same-kind proof configuration (starting with a real T=10
pilot) to estimate larger proof wall times. It never fills gaps with estimates:
an over-budget configuration is recorded as skipped with its evidence, and a
timed-out process retains its partial raw logs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_DIR = REPO_ROOT / "bench-results" / "2026-11-08"
TARGET_TRIPLE = "aarch64-apple-darwin"
DEFAULT_BINARY = REPO_ROOT / "target" / TARGET_TRIPLE / "release" / "baseline-host"
DEFAULT_SEED_HEX = "5341522d5a4b2d76302e34622d666978747572652d736565642d303030312121"
DEFAULT_T_VALUES = (10, 100, 1000)
DEFAULT_RECEIPT_KINDS = ("composite", "succinct")
NORMAL_SAMPLE_COUNT = 3
LONG_RUN_SECONDS = 30 * 60
MAX_CONFIG_SECONDS = 90 * 60


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def positive_csv(values: str) -> tuple[int, ...]:
    try:
        parsed = tuple(int(value.strip()) for value in values.split(",") if value.strip())
    except ValueError as error:
        raise argparse.ArgumentTypeError("T values must be comma-separated positive integers") from error
    if not parsed or any(value <= 0 for value in parsed) or len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("T values must be non-empty, positive, and unique")
    return parsed


def receipt_kinds(values: str) -> tuple[str, ...]:
    parsed = tuple(value.strip() for value in values.split(",") if value.strip())
    supported = set(DEFAULT_RECEIPT_KINDS)
    if not parsed or any(value not in supported for value in parsed) or len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("receipt kinds must be unique values from composite,succinct")
    return parsed


def seed_hex(value: str) -> str:
    value = value.removeprefix("0x").lower()
    if len(value) != 64:
        raise argparse.ArgumentTypeError("seed must be exactly 64 hexadecimal characters")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("seed must be hexadecimal") from error
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY, help="pre-built baseline-host binary")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--resume", action="store_true", help="continue an existing results.json")
    parser.add_argument("--build", action="store_true", help="build host before timing (never included in measurements)")
    parser.add_argument("--build-timeout-seconds", type=float, default=30 * 60)
    parser.add_argument("--execute-only", action="store_true", help="stop after standalone execution preflight")
    parser.add_argument("--t-values", type=positive_csv, default=DEFAULT_T_VALUES, metavar="10,100,1000")
    parser.add_argument("--receipt-kinds", type=receipt_kinds, default=DEFAULT_RECEIPT_KINDS)
    parser.add_argument("--seed", type=seed_hex, default=DEFAULT_SEED_HEX)
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=MAX_CONFIG_SECONDS,
        help="maximum wall time for one fresh-process invocation (default: 5400)",
    )
    parser.add_argument(
        "--max-config-seconds",
        type=float,
        default=MAX_CONFIG_SECONDS,
        help="hard cumulative limit for one T/receipt-kind configuration (default: 5400)",
    )
    arguments = parser.parse_args()
    if arguments.timeout_seconds <= 0 or arguments.max_config_seconds <= 0:
        parser.error("timeout values must be positive")
    if arguments.timeout_seconds > arguments.max_config_seconds:
        parser.error("--timeout-seconds cannot exceed --max-config-seconds")
    if arguments.build_timeout_seconds <= 0:
        parser.error("--build-timeout-seconds must be positive")
    if 10 not in arguments.t_values:
        parser.error("--t-values must include 10 because same-kind T=10 proof pilots anchor cutoff estimates")
    return arguments


def atomic_write_bytes(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(contents)
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def progress(message: str) -> None:
    print(f"[benchmark] {message}", flush=True)


def command_output(command: list[str], timeout: float = 15.0) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "unavailable", "error": str(error)}
    if completed.returncode != 0:
        return {
            "status": "unavailable",
            "return_code": completed.returncode,
            "error": completed.stderr.strip() or completed.stdout.strip(),
        }
    return {"status": "ok", "value": completed.stdout.strip()}


def hardware_inventory() -> dict[str, Any]:
    """Collect only public, benchmark-relevant hardware fields.

    Do not retain system_profiler serial numbers, UUIDs, or any other identity
    material. If the command is unavailable, the report says so rather than
    inventing machine facts.
    """

    inventory: dict[str, Any] = {
        "captured_at": utc_now(),
        "uname_machine": command_output(["uname", "-m"]),
        "macos_product_version": command_output(["sw_vers", "-productVersion"]),
        "online_processors": command_output(["getconf", "NPROCESSORS_ONLN"]),
        "rustc_version": command_output(["rustc", "-Vv"]),
        "cargo_version": command_output(["cargo", "--version"]),
        "rustc_risc0_version": command_output(["rustc", "+risc0", "-Vv"]),
        "cargo_risc0_version": command_output(["cargo", "+risc0", "-Vv"]),
        "rzup_show": command_output(["rzup", "show"]),
        "r0vm_version": command_output(["r0vm", "--version"]),
    }
    profile = command_output(["system_profiler", "SPHardwareDataType", "-json"], timeout=30.0)
    if profile.get("status") != "ok":
        inventory["hardware"] = {
            "status": "unavailable",
            "source": "system_profiler SPHardwareDataType -json",
            "error": profile.get("error", "unknown error"),
        }
        return inventory
    try:
        raw = json.loads(profile["value"])
        entry = raw["SPHardwareDataType"][0]
        inventory["hardware"] = {
            "status": "ok",
            "source": "system_profiler SPHardwareDataType -json (filtered)",
            "chip_type": entry.get("chip_type"),
            "physical_memory": entry.get("physical_memory"),
            "number_processors": entry.get("number_processors"),
            "machine_model": entry.get("machine_model"),
        }
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        inventory["hardware"] = {
            "status": "unavailable",
            "source": "system_profiler SPHardwareDataType -json (filtered)",
            "error": f"could not parse filtered fields: {error}",
        }
    return inventory


def benchmark_environment() -> tuple[dict[str, str], dict[str, str]]:
    environment = os.environ.copy()
    inherited = {
        name: environment[name]
        for name in ("RISC0_PROVER", "RISC0_EXECUTOR", "RISC0_DEV_MODE", "RISC0_BACKEND", "RAYON_NUM_THREADS")
        if name in environment
    }
    # v3.0.6 has no RISC0_BACKEND selector. CPU is selected by host Cargo
    # features (default-features=false, no cuda) and its documented source
    # fallback; retain no stale purported backend override in a measurement.
    environment.pop("RISC0_BACKEND", None)
    environment.update({"RISC0_PROVER": "local", "RISC0_EXECUTOR": "local", "RISC0_DEV_MODE": "0"})
    return environment, inherited


def pump(stream: BinaryIO, destination: BinaryIO) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            destination.write(chunk)
            destination.flush()
    finally:
        stream.close()


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    else:
        process.terminate()
    try:
        process.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    else:
        process.kill()
    process.wait(timeout=15)


def parse_host_json(stdout_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        lines = stdout_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        return None, f"could not read raw stdout: {error}"
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value, None
    return None, "no JSON object found on stdout"


def run_logged(
    command: list[str],
    *,
    environment: dict[str, str],
    raw_dir: Path,
    run_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Run one process while streaming all output directly to durable logs."""

    stdout_path = raw_dir / f"{run_id}.stdout.log"
    stderr_path = raw_dir / f"{run_id}.stderr.log"
    command_path = raw_dir / f"{run_id}.command.json"
    start_wall = time.monotonic()
    started_at = utc_now()
    atomic_write_json(
        command_path,
        {
            "command": command,
            "cwd": str(REPO_ROOT),
            "started_at": started_at,
            "timeout_seconds": timeout_seconds,
        },
    )
    record: dict[str, Any] = {
        "id": run_id,
        "command": command,
        "started_at": started_at,
        "timeout_seconds": timeout_seconds,
        "raw": {
            "stdout": str(stdout_path.relative_to(raw_dir.parent)),
            "stderr": str(stderr_path.relative_to(raw_dir.parent)),
            "command": str(command_path.relative_to(raw_dir.parent)),
        },
        "timed_out": False,
    }
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                cwd=REPO_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            stderr_file.write(f"could not start process: {error}\n".encode("utf-8", errors="replace"))
            record.update({"return_code": None, "spawn_error": str(error)})
            record["wall_elapsed_ms"] = (time.monotonic() - start_wall) * 1000
            return record
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = threading.Thread(target=pump, args=(process.stdout, stdout_file), daemon=True)
        stderr_thread = threading.Thread(target=pump, args=(process.stderr, stderr_file), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            stop_process_group(process)
        stdout_thread.join()
        stderr_thread.join()
        record["return_code"] = process.returncode
    record["wall_elapsed_ms"] = (time.monotonic() - start_wall) * 1000
    if not record["timed_out"] and record["return_code"] == 0:
        host_result, parse_error = parse_host_json(stdout_path)
        if host_result is not None:
            record["host_result"] = host_result
        else:
            record["parse_error"] = parse_error
    return record


def initial_config() -> dict[str, Any]:
    return {"status": "pending", "runs": [], "summary": None}


def new_results(arguments: argparse.Namespace, inherited_environment: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": "sar-zk-benchmark-results-v1",
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "plan": {
            "t_values": list(arguments.t_values),
            "receipt_kinds": list(arguments.receipt_kinds),
            "seed_hex": arguments.seed,
            "normal_sample_count": NORMAL_SAMPLE_COUNT,
            "long_run_threshold_seconds": LONG_RUN_SECONDS,
            "max_config_seconds": arguments.max_config_seconds,
            "per_process_timeout_seconds": arguments.timeout_seconds,
            "order": "all standalone execution configurations first, then one T=10 proof pilot per receipt kind, then larger proofs",
            "cutoff_policy": "Run a same-kind T=10 proof pilot first. For each larger T, use the largest completed smaller same-kind proof configuration and standalone execution-cycle scaling. Skip only when one estimated proof wall time exceeds the hard per-configuration limit. Fewer than three samples are retained only after an actual run exceeds 30 minutes or the cumulative configuration budget is exhausted.",
        },
        "environment": {
            "hardware": hardware_inventory(),
            "inherited_selected_environment": inherited_environment,
            "measurement_environment": {
                "RISC0_PROVER": "local",
                "RISC0_EXECUTOR": "local",
                "RISC0_DEV_MODE": "0",
                "RISC0_BACKEND": "unset; unsupported selector in RISC Zero v3.0.6",
            },
        },
        "artifact_identity": None,
        "build": None,
        "execution": {str(t): initial_config() for t in arguments.t_values},
        "proofs": {
            kind: {str(t): initial_config() for t in arguments.t_values}
            for kind in arguments.receipt_kinds
        },
        "events": [],
    }


def current_artifact_identity(binary: Path) -> dict[str, Any]:
    cargo_lock = REPO_ROOT / "Cargo.lock"
    if not binary.is_file():
        raise RuntimeError(f"benchmark binary is absent: {binary}")
    if not cargo_lock.is_file():
        raise RuntimeError(f"Cargo.lock is absent: {cargo_lock}")
    return {
        "binary": {"path": str(binary), "sha256": sha256_file(binary)},
        "cargo_lock": {"path": str(cargo_lock), "sha256": sha256_file(cargo_lock)},
        # Filled from the first successful host JSON, then checked on every
        # later run so receipts cannot be silently mixed across guest images.
        "image_id_words_le": None,
    }


def bind_or_check_image_identity(results: dict[str, Any], record: dict[str, Any]) -> None:
    host = record.get("host_result")
    if not isinstance(host, dict) or host.get("status") != "ok":
        return
    # `number_at` intentionally only navigates scalar numbers, whereas image
    # IDs are arrays. Extract and validate this boundary separately.
    raw_image_id = host.get("image", {}).get("id_words_le") if isinstance(host.get("image"), dict) else None
    if not (
        isinstance(raw_image_id, list)
        and len(raw_image_id) == 8
        and all(isinstance(word, int) and 0 <= word <= 0xFFFF_FFFF for word in raw_image_id)
    ):
        raise RuntimeError(f"successful host result {record.get('id')} lacks a valid image.id_words_le")
    identity = results.get("artifact_identity")
    if not isinstance(identity, dict):
        raise RuntimeError("benchmark artifact identity was not initialized")
    expected = identity.get("image_id_words_le")
    if expected is None:
        identity["image_id_words_le"] = raw_image_id
    elif expected != raw_image_id:
        raise RuntimeError(
            f"host image ID changed within one benchmark dataset: expected {expected}, got {raw_image_id}"
        )
    runtime = host.get("runtime") if isinstance(host.get("runtime"), dict) else {}
    resource = host.get("resource") if isinstance(host.get("resource"), dict) else {}
    results.setdefault(
        "observed_runtime",
        {
            "risc0_zkvm_version": runtime.get("risc0_zkvm_version"),
            "available_parallelism": runtime.get("available_parallelism"),
            "rayon_current_num_threads_after_timing": resource.get("rayon_current_num_threads_after_timing"),
            "rayon_num_threads_env": resource.get("rayon_num_threads_env"),
        },
    )


def ensure_compatible_resume(results: dict[str, Any], arguments: argparse.Namespace) -> None:
    plan = results.get("plan", {})
    expected = {
        "t_values": list(arguments.t_values),
        "receipt_kinds": list(arguments.receipt_kinds),
        "seed_hex": arguments.seed,
    }
    actual = {key: plan.get(key) for key in expected}
    if actual != expected:
        raise RuntimeError(
            "existing results plan differs from requested plan; use its original arguments or choose a new --results-dir"
        )


def ensure_matching_artifact_identity(results: dict[str, Any], live: dict[str, Any]) -> None:
    recorded = results.get("artifact_identity")
    if not isinstance(recorded, dict):
        raise RuntimeError("existing results lack artifact identity; choose a new results directory")
    for field in ("binary", "cargo_lock"):
        if recorded.get(field) != live.get(field):
            raise RuntimeError(
                f"{field} fingerprint differs from the existing dataset; refusing to mix benchmark artifacts"
            )


def ensure_artifacts_still_frozen(results: dict[str, Any]) -> None:
    identity = results.get("artifact_identity")
    if not isinstance(identity, dict) or not isinstance(identity.get("binary"), dict):
        raise RuntimeError("benchmark artifact identity was not initialized")
    binary_path = Path(identity["binary"].get("path", ""))
    live = current_artifact_identity(binary_path)
    ensure_matching_artifact_identity(results, live)


def number_at(value: dict[str, Any], path: Iterable[str]) -> float | int | None:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if isinstance(current, bool) or not isinstance(current, (int, float)) or not math.isfinite(current):
        return None
    return current


def successful_runs(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        run
        for run in config.get("runs", [])
        if not run.get("timed_out")
        and run.get("return_code") == 0
        and isinstance(run.get("host_result"), dict)
        and run["host_result"].get("status") == "ok"
    ]


def wall_elapsed_ms(config: dict[str, Any]) -> float:
    return sum(
        float(run["wall_elapsed_ms"])
        for run in config.get("runs", [])
        if isinstance(run.get("wall_elapsed_ms"), (int, float))
    )


def median_for(runs: list[dict[str, Any]], path: tuple[str, ...]) -> float | int | None:
    values = [number_at(run["host_result"], path) for run in runs]
    numeric = [value for value in values if value is not None]
    return statistics.median(numeric) if numeric else None


def refresh_summary(config: dict[str, Any], mode: str) -> None:
    runs = successful_runs(config)
    if not runs:
        config["summary"] = None
        return
    summary: dict[str, Any] = {
        "successful_samples": len(runs),
        "all_attempts": len(config.get("runs", [])),
        "median_wall_elapsed_ms": statistics.median(float(run["wall_elapsed_ms"]) for run in runs),
        "median_total_cycles": median_for(runs, ("cycles", "total_cycles")),
        "median_user_cycles": median_for(runs, ("cycles", "user_cycles")),
        "median_segments": median_for(runs, ("cycles", "segments")),
        "median_peak_rss_bytes": median_for(runs, ("resource", "peak_rss", "bytes")),
    }
    if mode == "execute":
        summary["median_execution_ms"] = median_for(runs, ("timing_ms", "execution"))
    else:
        summary.update(
            {
                "median_proof_generation_ms": median_for(runs, ("timing_ms", "proof_generation")),
                "median_receipt_verify_ms": median_for(runs, ("timing_ms", "receipt_verify")),
                "median_fixture_generation_ms": median_for(runs, ("timing_ms", "fixture_generation")),
                "median_receipt_bincode_1_3_bytes": median_for(
                    runs, ("receipt", "bincode_1_3_bytes")
                ),
            }
        )
    config["summary"] = summary


def format_number(value: Any, digits: int = 1) -> str:
    if value is None:
        return "—"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return str(value)


def markdown_report(results: dict[str, Any]) -> str:
    plan = results["plan"]
    lines = [
        "# SAR-ZK zkVM baseline results",
        "",
        f"Updated: `{results['updated_at']}`",
        "",
        "This report contains only completed measurements. A skipped or timed-out row is not a performance result; inspect its raw logs and recorded rationale in `results.json`.",
        "",
        "## Method",
        "",
        f"- Seed: `{plan['seed_hex']}`",
        f"- Requested T values: {', '.join(map(str, plan['t_values']))}",
        "- CPU selection: `risc0-zkvm = =3.0.6` with `default-features = false`, `std+prove`, no CUDA; fresh processes set `RISC0_PROVER=local`, `RISC0_EXECUTOR=local`, and `RISC0_DEV_MODE=0`. `RISC0_BACKEND` is intentionally unset because v3.0.6 has no such selector.",
        "- Proof-generation timing excludes fixture creation, native relation checks, receipt serialization, receipt verification, and receipt-artifact I/O. Process peak RSS covers the full process lifetime. Larger-T cutoff estimates anchor to the nearest completed smaller same-kind proof configuration, not blindly to T=10.",
        "- Each proof artifact is bincode 1.3 bytes plus an expected-journal sidecar, written after timing and independently re-verifiable with `baseline-host verify --receipt <path>`.",
        "",
    ]
    observed_runtime = results.get("observed_runtime")
    if isinstance(observed_runtime, dict):
        lines.extend(
            [
                "Observed host runtime: available parallelism `{available}`, Rayon pool width after timing `{rayon}`, `RAYON_NUM_THREADS` `{rayon_env}`.".format(
                    available=observed_runtime.get("available_parallelism", "unknown"),
                    rayon=observed_runtime.get("rayon_current_num_threads_after_timing", "unknown"),
                    rayon_env=observed_runtime.get("rayon_num_threads_env", "unset"),
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## Standalone execution preflight",
            "",
            "| T | status | successful samples | execution median ms | total cycles | user cycles | segments | peak RSS bytes |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for t in plan["t_values"]:
        config = results["execution"][str(t)]
        summary = config.get("summary") or {}
        lines.append(
            "| {t} | {status} | {samples} | {execution} | {total} | {user} | {segments} | {rss} |".format(
                t=t,
                status=config.get("status", "pending"),
                samples=summary.get("successful_samples", 0),
                execution=format_number(summary.get("median_execution_ms")),
                total=format_number(summary.get("median_total_cycles"), 0),
                user=format_number(summary.get("median_user_cycles"), 0),
                segments=format_number(summary.get("median_segments"), 0),
                rss=format_number(summary.get("median_peak_rss_bytes"), 0),
            )
        )
    lines.extend(
        [
            "",
            "## Proofs",
            "",
            "| receipt | T | status | successful samples | proof-generation median ms | verify median ms | receipt bytes | total cycles | peak RSS bytes |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for kind in plan["receipt_kinds"]:
        for t in plan["t_values"]:
            config = results["proofs"][kind][str(t)]
            summary = config.get("summary") or {}
            lines.append(
                "| {kind} | {t} | {status} | {samples} | {proof} | {verify} | {bytes_} | {cycles} | {rss} |".format(
                    kind=kind,
                    t=t,
                    status=config.get("status", "pending"),
                    samples=summary.get("successful_samples", 0),
                    proof=format_number(summary.get("median_proof_generation_ms")),
                    verify=format_number(summary.get("median_receipt_verify_ms")),
                    bytes_=format_number(summary.get("median_receipt_bincode_1_3_bytes"), 0),
                    cycles=format_number(summary.get("median_total_cycles"), 0),
                    rss=format_number(summary.get("median_peak_rss_bytes"), 0),
                )
            )
    cutoff_rows: list[str] = []
    for kind in plan["receipt_kinds"]:
        for t in plan["t_values"]:
            config = results["proofs"][kind][str(t)]
            if config.get("status") == "skipped_cutoff":
                estimate = config.get("cutoff_estimate", {})
                cutoff_rows.append(
                    "- `{kind}`, T={t}: predicted one-proof wall time {estimate} ms exceeds the {limit} s configuration limit; evidence is recorded in `results.json`.".format(
                        kind=kind,
                        t=t,
                        estimate=format_number(estimate.get("predicted_one_wall_ms")),
                        limit=plan["max_config_seconds"],
                    )
                )
    if cutoff_rows:
        lines.extend(["", "## Cutoff decisions", "", *cutoff_rows])
    lines.extend(
        [
            "",
            "## Environment",
            "",
            "Filtered hardware and tool-version evidence is stored verbatim in `results.json`; serial numbers and platform UUIDs are intentionally not collected.",
        ]
    )
    return "\n".join(lines) + "\n"


def persist(results: dict[str, Any], results_dir: Path) -> None:
    for config in results["execution"].values():
        refresh_summary(config, "execute")
    for kind_configs in results["proofs"].values():
        for config in kind_configs.values():
            refresh_summary(config, "prove")
    results["updated_at"] = utc_now()
    atomic_write_json(results_dir / "results.json", results)
    atomic_write_bytes(results_dir / "results.md", markdown_report(results).encode("utf-8"))


def terminal(config: dict[str, Any]) -> bool:
    return config.get("status") in {"complete", "skipped_cutoff", "failed", "timed_out", "stopped_budget"}


def terminal_failures(results: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for t, config in results["execution"].items():
        if config.get("status") in {"failed", "timed_out", "stopped_budget"}:
            failures.append(f"execute T={t}: {config.get('status')}")
    for kind, by_t in results["proofs"].items():
        for t, config in by_t.items():
            if config.get("status") in {"failed", "timed_out", "stopped_budget"}:
                failures.append(f"{kind} T={t}: {config.get('status')}")
    return failures


def execution_preflight_failures(results: dict[str, Any]) -> list[str]:
    return [
        f"execute T={t}: {config.get('status')}"
        for t, config in results["execution"].items()
        if config.get("status") != "complete"
    ]


def host_ok(record: dict[str, Any]) -> bool:
    return (
        not record.get("timed_out")
        and record.get("return_code") == 0
        and isinstance(record.get("host_result"), dict)
        and record["host_result"].get("status") == "ok"
    )


def append_attempt(
    config: dict[str, Any],
    results: dict[str, Any],
    results_dir: Path,
    command: list[str],
    environment: dict[str, str],
    raw_dir: Path,
    run_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    ensure_artifacts_still_frozen(results)
    progress(f"start {run_id} (timeout {timeout_seconds:.1f}s)")
    record = run_logged(
        command,
        environment=environment,
        raw_dir=raw_dir,
        run_id=run_id,
        timeout_seconds=timeout_seconds,
    )
    config["runs"].append(record)
    try:
        bind_or_check_image_identity(results, record)
    except RuntimeError as error:
        record["identity_error"] = str(error)
        config["status"] = "failed"
        config["reason"] = "artifact identity check failed"
        results["events"].append(
            {"at": utc_now(), "event": "artifact_identity_failed", "id": run_id, "error": str(error)}
        )
        persist(results, results_dir)
        raise
    results["events"].append(
        {
            "at": utc_now(),
            "event": "attempt_completed",
            "id": run_id,
            "timed_out": record.get("timed_out", False),
            "return_code": record.get("return_code"),
            "wall_elapsed_ms": record.get("wall_elapsed_ms"),
        }
    )
    persist(results, results_dir)
    progress(
        "end {id} return={return_code} timeout={timed_out} wall={wall:.1f}ms".format(
            id=run_id,
            return_code=record.get("return_code"),
            timed_out=record.get("timed_out", False),
            wall=float(record.get("wall_elapsed_ms", 0)),
        )
    )
    return record


def classify_failed_attempt(config: dict[str, Any], record: dict[str, Any]) -> None:
    if record.get("timed_out"):
        config["status"] = "timed_out"
        config["reason"] = "process hit its safe timeout; partial stdout/stderr are retained in raw logs"
    else:
        config["status"] = "failed"
        config["reason"] = "fresh-process command failed or did not emit a successful host JSON result"


def command_timeout(arguments: argparse.Namespace, config: dict[str, Any]) -> float | None:
    remaining = arguments.max_config_seconds * 1000 - wall_elapsed_ms(config)
    if remaining <= 0:
        return None
    return min(arguments.timeout_seconds, remaining / 1000)


def run_execution_config(
    results: dict[str, Any],
    results_dir: Path,
    raw_dir: Path,
    arguments: argparse.Namespace,
    environment: dict[str, str],
    t: int,
) -> None:
    config = results["execution"][str(t)]
    if terminal(config):
        return
    successes = successful_runs(config)
    if successes and float(successes[-1]["wall_elapsed_ms"]) > LONG_RUN_SECONDS * 1000:
        config["status"] = "complete"
        config["sampling_note"] = "existing execution sample exceeded 30 minutes; fewer than three samples retained"
        persist(results, results_dir)
        return
    while len(successes) < NORMAL_SAMPLE_COUNT:
        timeout_seconds = command_timeout(arguments, config)
        if timeout_seconds is None:
            config["status"] = "stopped_budget"
            config["reason"] = "cumulative process wall time reached the 90-minute configuration limit"
            persist(results, results_dir)
            return
        attempt = len(config["runs"]) + 1
        record = append_attempt(
            config,
            results,
            results_dir,
            [str(arguments.binary), "execute", "--t", str(t), "--seed", arguments.seed],
            environment,
            raw_dir,
            f"execute-t{t}-attempt{attempt}",
            timeout_seconds,
        )
        if not host_ok(record):
            classify_failed_attempt(config, record)
            persist(results, results_dir)
            return
        successes = successful_runs(config)
        if float(record["wall_elapsed_ms"]) > LONG_RUN_SECONDS * 1000:
            config["status"] = "complete"
            config["sampling_note"] = "stopped after a run exceeded 30 minutes"
            persist(results, results_dir)
            return
    config["status"] = "complete"
    persist(results, results_dir)


def execution_cycles(results: dict[str, Any], t: int) -> float | None:
    config = results["execution"][str(t)]
    return median_for(successful_runs(config), ("cycles", "total_cycles"))


def first_success(config: dict[str, Any]) -> dict[str, Any] | None:
    successes = successful_runs(config)
    return successes[0] if successes else None


def proof_cutoff_estimate(
    results: dict[str, Any], kind: str, t: int
) -> dict[str, Any] | None:
    # The T=10 proof is always the first same-kind pilot, but a larger
    # completed configuration is a better throughput anchor for a still larger
    # T: fixed recursion/setup work should not be multiplied from T=10.
    candidates = [
        candidate
        for candidate in results["plan"]["t_values"]
        if candidate < t
        and results["proofs"][kind][str(candidate)].get("status") == "complete"
        and successful_runs(results["proofs"][kind][str(candidate)])
    ]
    if t == 10:
        candidates = [10] if successful_runs(results["proofs"][kind]["10"]) else []
    if not candidates:
        return None
    anchor_t = max(candidates)
    anchor_config = results["proofs"][kind][str(anchor_t)]
    anchor_runs = successful_runs(anchor_config)
    anchor_cycles = execution_cycles(results, anchor_t)
    target_cycles = execution_cycles(results, t)
    if anchor_cycles is None or target_cycles is None or anchor_cycles <= 0:
        return None
    anchor_proof_ms = median_for(anchor_runs, ("timing_ms", "proof_generation"))
    anchor_wall_ms = statistics.median(float(run["wall_elapsed_ms"]) for run in anchor_runs)
    if anchor_proof_ms is None or anchor_wall_ms <= 0:
        return None
    scale = target_cycles / anchor_cycles
    return {
        "method": "largest completed smaller same-kind proof configuration scaled by standalone execution total cycles",
        "first_same_kind_pilot_t": 10,
        "anchor_t": anchor_t,
        "anchor_run_ids": [run["id"] for run in anchor_runs],
        "anchor_successful_samples": len(anchor_runs),
        "anchor_execution_total_cycles": anchor_cycles,
        "target_execution_total_cycles": target_cycles,
        "cycle_scale": scale,
        "anchor_median_proof_generation_ms": anchor_proof_ms,
        "anchor_median_wall_elapsed_ms": anchor_wall_ms,
        "predicted_one_proof_generation_ms": anchor_proof_ms * scale,
        "predicted_one_wall_ms": anchor_wall_ms * scale,
        "predicted_three_wall_ms": anchor_wall_ms * scale * NORMAL_SAMPLE_COUNT,
    }


def run_proof_config(
    results: dict[str, Any],
    results_dir: Path,
    raw_dir: Path,
    artifacts_dir: Path,
    arguments: argparse.Namespace,
    environment: dict[str, str],
    kind: str,
    t: int,
) -> None:
    config = results["proofs"][kind][str(t)]
    if terminal(config):
        return
    if not successful_runs(results["execution"][str(t)]):
        config["status"] = "failed"
        config["reason"] = "no successful standalone execution evidence exists for this T"
        persist(results, results_dir)
        return

    # A real same-kind T=10 proof is the only permissible calibration point.
    pilot_config = results["proofs"][kind]["10"]
    if t == 10 and not successful_runs(config):
        timeout_seconds = command_timeout(arguments, config)
        if timeout_seconds is None:
            config["status"] = "stopped_budget"
            config["reason"] = "no remaining wall-time budget for T=10 proof pilot"
            persist(results, results_dir)
            return
        attempt = len(config["runs"]) + 1
        receipt_path = artifacts_dir / f"{kind}-t{t}-attempt{attempt}.receipt"
        record = append_attempt(
            config,
            results,
            results_dir,
            [
                str(arguments.binary),
                "prove",
                "--t",
                str(t),
                "--seed",
                arguments.seed,
                "--receipt-kind",
                kind,
                "--receipt-out",
                str(receipt_path),
            ],
            environment,
            raw_dir,
            f"prove-{kind}-t{t}-attempt{attempt}",
            timeout_seconds,
        )
        if not host_ok(record):
            classify_failed_attempt(config, record)
            persist(results, results_dir)
            return
        config["pilot_run_id"] = record["id"]
        persist(results, results_dir)

    if not successful_runs(pilot_config):
        config["status"] = "failed"
        config["reason"] = "same-kind T=10 proof pilot did not complete successfully"
        persist(results, results_dir)
        return

    estimate = proof_cutoff_estimate(results, kind, t)
    if estimate is None:
        config["status"] = "failed"
        config["reason"] = "could not compute an execution-cycle cutoff estimate from observed evidence"
        persist(results, results_dir)
        return
    config["cutoff_estimate"] = estimate
    if estimate["predicted_one_wall_ms"] > arguments.max_config_seconds * 1000:
        config["status"] = "skipped_cutoff"
        config["reason"] = "estimated one-proof wall time exceeds the hard 90-minute per-configuration limit"
        persist(results, results_dir)
        return

    desired_samples = NORMAL_SAMPLE_COUNT
    if estimate["predicted_three_wall_ms"] > arguments.max_config_seconds * 1000:
        config["forecast_note"] = (
            "three-sample wall-time extrapolation exceeds the 90-minute limit; continue sampling until an actual "
            "run exceeds 30 minutes or the cumulative configuration budget is exhausted"
        )
    successes = successful_runs(config)
    if successes and float(successes[-1]["wall_elapsed_ms"]) > LONG_RUN_SECONDS * 1000:
        config["status"] = "complete"
        config["sampling_note"] = "existing proof sample exceeded 30 minutes; fewer than three samples retained"
        persist(results, results_dir)
        return
    while len(successes) < desired_samples:
        timeout_seconds = command_timeout(arguments, config)
        if timeout_seconds is None:
            config["status"] = "stopped_budget"
            config["reason"] = "cumulative process wall time reached the 90-minute configuration limit"
            persist(results, results_dir)
            return
        attempt = len(config["runs"]) + 1
        receipt_path = artifacts_dir / f"{kind}-t{t}-attempt{attempt}.receipt"
        record = append_attempt(
            config,
            results,
            results_dir,
            [
                str(arguments.binary),
                "prove",
                "--t",
                str(t),
                "--seed",
                arguments.seed,
                "--receipt-kind",
                kind,
                "--receipt-out",
                str(receipt_path),
            ],
            environment,
            raw_dir,
            f"prove-{kind}-t{t}-attempt{attempt}",
            timeout_seconds,
        )
        if not host_ok(record):
            classify_failed_attempt(config, record)
            persist(results, results_dir)
            return
        successes = successful_runs(config)
        if float(record["wall_elapsed_ms"]) > LONG_RUN_SECONDS * 1000:
            config["status"] = "complete"
            config["sampling_note"] = "stopped after a proof run exceeded 30 minutes"
            persist(results, results_dir)
            return
    config["status"] = "complete"
    persist(results, results_dir)


def run_build(
    results: dict[str, Any], results_dir: Path, raw_dir: Path, arguments: argparse.Namespace, environment: dict[str, str]
) -> None:
    build_attempt = 1 + sum(1 for event in results["events"] if event.get("event") == "build_completed")
    run_id = f"build-host-attempt{build_attempt}"
    progress(f"start {run_id} (timeout {arguments.build_timeout_seconds:.1f}s)")
    record = run_logged(
        [
            "cargo",
            "+risc0",
            "build",
            "--release",
            "--target",
            TARGET_TRIPLE,
            "-p",
            "baseline-host",
        ],
        environment=environment,
        raw_dir=raw_dir,
        run_id=run_id,
        timeout_seconds=arguments.build_timeout_seconds,
    )
    results["build"] = record
    results["events"].append(
        {
            "at": utc_now(),
            "event": "build_completed",
            "timed_out": record.get("timed_out", False),
            "return_code": record.get("return_code"),
        }
    )
    persist(results, results_dir)
    progress(
        "end {id} return={return_code} timeout={timed_out} wall={wall:.1f}ms".format(
            id=run_id,
            return_code=record.get("return_code"),
            timed_out=record.get("timed_out", False),
            wall=float(record.get("wall_elapsed_ms", 0)),
        )
    )
    if record.get("timed_out") or record.get("return_code") != 0:
        raise RuntimeError(f"pre-measurement host build failed; inspect raw/{run_id}.* logs")


def main() -> int:
    arguments = parse_args()
    arguments.binary = arguments.binary.resolve()
    results_dir = arguments.results_dir.resolve()
    raw_dir = results_dir / "raw"
    artifacts_dir = results_dir / "receipts"
    results_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    environment, inherited_environment = benchmark_environment()
    results_path = results_dir / "results.json"
    if arguments.resume:
        if not results_path.exists():
            raise RuntimeError(f"--resume requested but {results_path} does not exist")
        results = json.loads(results_path.read_text(encoding="utf-8"))
        ensure_compatible_resume(results, arguments)
        results["events"].append({"at": utc_now(), "event": "resume_requested"})
    else:
        if results_path.exists():
            raise RuntimeError(f"{results_path} already exists; use --resume or choose a new --results-dir")
        results = new_results(arguments, inherited_environment)
        persist(results, results_dir)

    if arguments.build:
        progress(f"building host for {TARGET_TRIPLE} before measurement")
        run_build(results, results_dir, raw_dir, arguments, environment)
    if not arguments.binary.is_file():
        raise RuntimeError(
            f"benchmark binary is absent: {arguments.binary}; build it first or use --build (build time is excluded)"
        )
    live_identity = current_artifact_identity(arguments.binary)
    if arguments.resume:
        ensure_matching_artifact_identity(results, live_identity)
        results["events"].append({"at": utc_now(), "event": "resumed"})
    else:
        results["artifact_identity"] = live_identity
    persist(results, results_dir)
    progress(
        "starting plan with binary sha256={binary} cargo-lock sha256={lock}".format(
            binary=live_identity["binary"]["sha256"], lock=live_identity["cargo_lock"]["sha256"]
        )
    )

    # Every requested standalone execution completes before the first proof
    # pilot, so cost evidence exists before proof work begins.
    for t in arguments.t_values:
        run_execution_config(results, results_dir, raw_dir, arguments, environment, t)
    if arguments.execute_only:
        results["events"].append({"at": utc_now(), "event": "execute_only_complete"})
        persist(results, results_dir)
        failures = terminal_failures(results)
        if failures:
            progress("execute-only plan finished with terminal failures: " + "; ".join(failures))
            return 1
        progress("execute-only plan complete")
        return 0

    preflight_failures = execution_preflight_failures(results)
    if preflight_failures:
        results["events"].append(
            {
                "at": utc_now(),
                "event": "proofs_not_started_incomplete_execution_preflight",
                "failures": preflight_failures,
            }
        )
        persist(results, results_dir)
        progress("not starting proofs: " + "; ".join(preflight_failures))
        return 1

    # Each receipt kind gets its own T=10 pilot first. Larger T values then use
    # that same-kind pilot plus already observed execution cycles for cutoff.
    ensure_artifacts_still_frozen(results)
    results["events"].append({"at": utc_now(), "event": "artifact_revalidated_before_proofs"})
    persist(results, results_dir)
    progress("binary and Cargo.lock fingerprints revalidated; starting proof pilots")
    for kind in arguments.receipt_kinds:
        run_proof_config(results, results_dir, raw_dir, artifacts_dir, arguments, environment, kind, 10)
        for t in sorted(arguments.t_values):
            if t != 10:
                run_proof_config(results, results_dir, raw_dir, artifacts_dir, arguments, environment, kind, t)
    results["events"].append({"at": utc_now(), "event": "benchmark_plan_complete"})
    persist(results, results_dir)
    failures = terminal_failures(results)
    if failures:
        progress("benchmark plan finished with terminal failures: " + "; ".join(failures))
        return 1
    progress("benchmark plan complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, json.JSONDecodeError) as error:
        print(f"run_benchmarks.py: {error}", file=sys.stderr)
        raise SystemExit(2)
