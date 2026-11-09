#!/usr/bin/env python3
"""Capture the final arithmetic and negative validation evidence verbatim."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = REPO_ROOT / "target" / "aarch64-apple-darwin" / "release" / "baseline-host"
DEFAULT_OUTPUT = REPO_ROOT / "bench-results" / "2026-11-08" / "validation"
NEGATIVE_CASES = ("wrong-tool", "wrong-transcript", "wrong-signature", "wrong-nullifier")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--t", type=int, default=10)
    arguments = parser.parse_args()
    if arguments.t <= 0:
        parser.error("--t must be positive")
    return arguments


def atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(contents)
    os.replace(temporary, path)


def json_from_stdout(stdout: bytes) -> dict[str, Any]:
    for line in reversed(stdout.decode("utf-8", errors="replace").splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    raise RuntimeError("baseline-host did not emit a JSON object on stdout")


def capture(name: str, command: list[str], environment: dict[str, str], output_dir: Path) -> None:
    print(f"[validation] start {name}", flush=True)
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    atomic_write(output_dir / f"{name}.stdout.log", completed.stdout)
    atomic_write(output_dir / f"{name}.stderr.log", completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(f"{name} exited {completed.returncode}; inspect its raw logs")
    result = json_from_stdout(completed.stdout)
    atomic_write(
        output_dir / f"{name}.json",
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(f"[validation] end {name}: {result.get('status')}", flush=True)


def main() -> int:
    arguments = parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file():
        raise RuntimeError(f"baseline-host binary is absent: {binary}")
    environment = os.environ.copy()
    environment.update({"RISC0_PROVER": "local", "RISC0_EXECUTOR": "local", "RISC0_DEV_MODE": "0"})
    environment.pop("RISC0_BACKEND", None)

    capture("check-arithmetic", [str(binary), "check-arithmetic"], environment, arguments.output_dir)
    for negative_case in NEGATIVE_CASES:
        capture(
            f"negative-{negative_case}",
            [str(binary), "negative", "--t", str(arguments.t), "--case", negative_case],
            environment,
            arguments.output_dir,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"capture_validation.py: {error}", file=sys.stderr)
        raise SystemExit(2)
