#!/usr/bin/env python3
# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Argon2id KDF cost benchmarking script for GUN-101.

Measures the wall-clock execution time of gun101.kdf.derive_key()
across various Argon2id parameters (memory cost, time cost, parallelism).
Produces human-readable tables or machine-readable CSV / JSON output.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import platform
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

# Ensure src/ is on sys.path so gun101 can be imported without installation
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from gun101 import config, kdf  # noqa: E402


@dataclass
class BenchmarkResult:
    label: str
    memory_mb: float
    memory_kb: int
    time_cost: int
    parallelism: int
    rounds: int
    min_seconds: float
    mean_seconds: float
    max_seconds: float


@contextmanager
def override_argon2_config(memory_cost: int, time_cost: int, parallelism: int):
    """Temporarily apply custom Argon2id parameters to gun101.config.

    Restores original production values upon exit to prevent side effects.
    """
    orig_memory = config.ARGON2_MEMORY_COST
    orig_time = config.ARGON2_TIME_COST
    orig_parallelism = config.ARGON2_PARALLELISM
    try:
        config.ARGON2_MEMORY_COST = memory_cost
        config.ARGON2_TIME_COST = time_cost
        config.ARGON2_PARALLELISM = parallelism
        yield
    finally:
        config.ARGON2_MEMORY_COST = orig_memory
        config.ARGON2_TIME_COST = orig_time
        config.ARGON2_PARALLELISM = orig_parallelism


def benchmark_setting(
    label: str,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
    password: str,
    salt: bytes,
    keyfile_bytes: bytes | None = None,
    rounds: int = 3,
    warmup: int = 1,
) -> BenchmarkResult:
    """Benchmark gun101.kdf.derive_key() with specific Argon2id parameters.

    Args:
        label: Descriptive label for this parameter configuration.
        memory_cost: Argon2 memory cost in KiB.
        time_cost: Argon2 time cost (iterations).
        parallelism: Argon2 parallelism (lanes / threads).
        password: Password string to derive key from.
        salt: Random or fixed salt bytes of length config.ARGON2_SALT_LEN.
        keyfile_bytes: Optional keyfile content bytes.
        rounds: Number of timed repetitions to record.
        warmup: Number of untimed warmup runs before measurement.

    Returns:
        BenchmarkResult with min, mean, and max execution times.
    """
    with override_argon2_config(memory_cost, time_cost, parallelism):
        # Warmup executions to prime CPU caches and runtime state
        for _ in range(warmup):
            kdf.derive_key(password, salt, keyfile_bytes)

        durations: list[float] = []
        for _ in range(rounds):
            t_start = time.perf_counter()
            derived = kdf.derive_key(password, salt, keyfile_bytes)
            t_elapsed = time.perf_counter() - t_start
            durations.append(t_elapsed)

            # Ensure derive_key returned expected key length
            if len(derived) != config.ARGON2_HASH_LEN:
                raise RuntimeError(
                    f"Expected derived key length {config.ARGON2_HASH_LEN}, got {len(derived)}"
                )

    return BenchmarkResult(
        label=label,
        memory_mb=round(memory_cost / 1024, 2),
        memory_kb=memory_cost,
        time_cost=time_cost,
        parallelism=parallelism,
        rounds=rounds,
        min_seconds=min(durations),
        mean_seconds=sum(durations) / len(durations),
        max_seconds=max(durations),
    )


def get_benchmark_configs(
    profile: str,
    custom_memories: Sequence[int] | None = None,
    custom_times: Sequence[int] | None = None,
    custom_parallelisms: Sequence[int] | None = None,
) -> list[tuple[str, int, int, int]]:
    """Generate a list of (label, memory_cost_kb, time_cost, parallelism) tuples."""
    if custom_memories or custom_times or custom_parallelisms:
        memories = custom_memories or [config.ARGON2_MEMORY_COST]
        times = custom_times or [config.ARGON2_TIME_COST]
        parallelisms = custom_parallelisms or [config.ARGON2_PARALLELISM]
        configs: list[tuple[str, int, int, int]] = []
        for m in memories:
            for t in times:
                for p in parallelisms:
                    label = f"Custom ({m // 1024}MB, t={t}, p={p})"
                    configs.append((label, m, t, p))
        return configs

    if profile == "production":
        return [
            (
                "Current Production Default",
                config.ARGON2_MEMORY_COST,
                config.ARGON2_TIME_COST,
                config.ARGON2_PARALLELISM,
            )
        ]

    if profile == "quick":
        return [
            ("Quick 64MB t=1 p=4", 65536, 1, 4),
            ("Quick 128MB t=2 p=4", 131072, 2, 4),
            ("Quick 256MB t=4 p=4 (Prod)", 262144, 4, 4),
        ]

    if profile == "matrix":
        memories = [65536, 131072, 262144]
        times = [1, 2, 3, 4]
        parallelisms = [1, 2, 4]
        configs = []
        for m in memories:
            for t in times:
                for p in parallelisms:
                    configs.append((f"Matrix ({m // 1024}MB, t={t}, p={p})", m, t, p))
        return configs

    # Default 'standard' profile: curated representative combinations
    # Includes reference baselines, memory scaling, iteration scaling, and parallelism scaling.
    standard_suite: list[tuple[str, int, int, int]] = [
        # Reference baselines
        ("Production Default (256MB, t=4, p=4)", 262144, 4, 4),
        ("OWASP Minimum (64MB, t=3, p=4)", 65536, 3, 4),
        ("RFC 9106 Interactive (64MB, t=3, p=1)", 65536, 3, 1),
        # Memory scaling (fixed t=4, p=4)
        ("Memory Scaling (64MB, t=4, p=4)", 65536, 4, 4),
        ("Memory Scaling (128MB, t=4, p=4)", 131072, 4, 4),
        ("Memory Scaling (512MB, t=4, p=4)", 524288, 4, 4),
        # Time cost scaling (fixed 256MB, p=4)
        ("Time Scaling (256MB, t=1, p=4)", 262144, 1, 4),
        ("Time Scaling (256MB, t=2, p=4)", 262144, 2, 4),
        ("Time Scaling (256MB, t=3, p=4)", 262144, 3, 4),
        # Parallelism scaling (fixed 256MB, t=4)
        ("Parallelism Scaling (256MB, t=4, p=1)", 262144, 4, 1),
        ("Parallelism Scaling (256MB, t=4, p=2)", 262144, 4, 2),
    ]
    return standard_suite


def format_table(results: Sequence[BenchmarkResult]) -> str:
    """Format benchmark results into a clear, aligned ASCII table."""
    headers = [
        "Configuration / Label",
        "Memory (MB)",
        "Memory (KB)",
        "Time",
        "Lanes",
        "Rounds",
        "Min (s)",
        "Mean (s)",
        "Max (s)",
    ]

    rows: list[list[str]] = []
    for r in results:
        rows.append(
            [
                r.label,
                f"{r.memory_mb:.1f}",
                str(r.memory_kb),
                str(r.time_cost),
                str(r.parallelism),
                str(r.rounds),
                f"{r.min_seconds:.4f}",
                f"{r.mean_seconds:.4f}",
                f"{r.max_seconds:.4f}",
            ]
        )

    # Determine column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def make_row(values: list[str]) -> str:
        # First column left-aligned, numeric columns right-aligned
        cells = [
            values[0].ljust(col_widths[0]),
            *(val.rjust(col_widths[i]) for i, val in enumerate(values[1:], start=1)),
        ]
        return " | ".join(cells)

    separator = "-+-".join("-" * w for w in col_widths)
    header_line = make_row(headers)

    lines = [
        "=" * len(header_line),
        "GUN-101 Argon2id KDF Benchmark",
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()}) | "
        f"Python: {platform.python_version()} | CPU Cores: {os.cpu_count() or 'unknown'}",
        "=" * len(header_line),
        header_line,
        separator,
    ]
    for row in rows:
        lines.append(make_row(row))
    lines.append("=" * len(header_line))
    return "\n".join(lines)


def format_csv(results: Sequence[BenchmarkResult]) -> str:
    """Format benchmark results into standard RFC-4180 CSV text."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "label",
            "memory_mb",
            "memory_kb",
            "time_cost",
            "parallelism",
            "rounds",
            "min_seconds",
            "mean_seconds",
            "max_seconds",
        ]
    )
    for r in results:
        writer.writerow(
            [
                r.label,
                r.memory_mb,
                r.memory_kb,
                r.time_cost,
                r.parallelism,
                r.rounds,
                f"{r.min_seconds:.6f}",
                f"{r.mean_seconds:.6f}",
                f"{r.max_seconds:.6f}",
            ]
        )
    return output.getvalue()


def format_json(results: Sequence[BenchmarkResult]) -> str:
    """Format benchmark results into JSON text."""
    return json.dumps([asdict(r) for r in results], indent=2)


def parse_args(args: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark Argon2id key derivation costs for GUN-101 (Issue #7).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--profile",
        choices=["standard", "quick", "production", "matrix"],
        default="standard",
        help="Predefined parameter suite to run.",
    )
    parser.add_argument(
        "--memory-costs",
        type=int,
        nargs="+",
        metavar="KB",
        help="Custom memory cost values in KiB (e.g. 65536 131072 262144).",
    )
    parser.add_argument(
        "--time-costs",
        type=int,
        nargs="+",
        metavar="ITER",
        help="Custom time cost values (iterations) (e.g. 1 2 3 4).",
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        nargs="+",
        metavar="LANES",
        help="Custom parallelism values (lanes) (e.g. 1 2 4).",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="Number of timed repetitions per parameter combination.",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="Number of untimed warmup runs before each timed round.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "csv", "json"],
        default="table",
        help="Output presentation format.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Optional file path to write results into (writes to stdout if omitted).",
    )
    parser.add_argument(
        "--with-keyfile",
        action="store_true",
        help="Include a 32-byte keyfile input in derive_key() calls.",
    )
    parser.add_argument(
        "--password",
        type=str,
        default="BenchmarkPassword123!",
        help="Sample password string to use for key derivation.",
    )
    return parser.parse_args(args)


def main(args: Sequence[str] | None = None) -> int:
    opts = parse_args(args)

    if opts.rounds < 1:
        sys.stderr.write("Error: --rounds must be at least 1\n")
        return 1
    if opts.warmup < 0:
        sys.stderr.write("Error: --warmup cannot be negative\n")
        return 1

    configs = get_benchmark_configs(
        profile=opts.profile,
        custom_memories=opts.memory_costs,
        custom_times=opts.time_costs,
        custom_parallelisms=opts.parallelism,
    )

    salt = os.urandom(config.ARGON2_SALT_LEN)
    keyfile_bytes = os.urandom(config.KEYFILE_LEN) if opts.with_keyfile else None

    # Print progress indicator if writing to a file or in verbose mode
    if opts.output:
        print(f"Running Argon2id benchmark ({len(configs)} configurations, {opts.rounds} rounds each)...")

    results: list[BenchmarkResult] = []
    for label, mem, t, p in configs:
        res = benchmark_setting(
            label=label,
            memory_cost=mem,
            time_cost=t,
            parallelism=p,
            password=opts.password,
            salt=salt,
            keyfile_bytes=keyfile_bytes,
            rounds=opts.rounds,
            warmup=opts.warmup,
        )
        results.append(res)

    if opts.format == "csv":
        formatted_output = format_csv(results)
    elif opts.format == "json":
        formatted_output = format_json(results)
    else:
        formatted_output = format_table(results)

    if opts.output:
        out_path = Path(opts.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(formatted_output, encoding="utf-8")
        print(f"Benchmark results successfully saved to: {out_path}")
    else:
        print(formatted_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
