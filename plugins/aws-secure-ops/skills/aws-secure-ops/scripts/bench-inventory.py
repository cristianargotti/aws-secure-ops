#!/usr/bin/env python3
"""Measure the inventory-load cost the gate pays on every aws command.

The gate (classify-aws-command.py) parses references/inventory/inventory.csv
(~17.8k rows) into an in-memory dict via load_inventory() on each invocation.
This benchmark quantifies that cost so any optimization is evidence-based:

  1. In-process: time load_inventory() exactly as the gate calls it, over
     ~50 iterations. Reports min / median / max in milliseconds.
  2. End-to-end: wrap a representative stamped mutation as a Bash hook event,
     feed it to the gate on stdin as a child process, and time the full round
     trip over ~30 runs. A non-aws control command (which the gate early-exits
     without loading the inventory) isolates the added latency the aws path
     pays over the non-aws path.

Verdict: if the median added latency per aws command is under ~30 ms, no index
is warranted -- the early-exit already skips non-aws commands, so the cost is
paid only on aws commands and is negligible against interpreter startup and the
network round trip of the aws call itself. Above that, a precompiled index is
recommended (but NOT implemented here: the gate is frozen this run).

Portable: pure stdlib, time.perf_counter, discovers its own interpreter. Runs
on macOS and Linux. Read-only -- never touches the real AWS account, settings,
or home directory; the child gate reads only the public inventory csv.
"""

import importlib.util
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "classify-aws-command.py"

INVENTORY_ITERS = 50
E2E_RUNS = 30

# A representative stamped mutation: an inline purpose stamp plus a guarded
# ec2 tag write. Neutral placeholders only -- no real account or resource.
STAMPED_MUTATION = (
    'AWS_SDK_UA_APP_ID="ex-bench-inventory" '
    "aws ec2 create-tags --resources i-0123456789abcdef0 "
    "--tags Key=purpose,Value=inventory-benchmark --profile example-profile"
)
# Control: a command with no aws invocation. The gate matches the aws regex,
# fails it, and exits before loading policy or inventory.
CONTROL_COMMAND = "echo hello && ls -la /tmp"


def load_classifier():
    """Import the frozen gate module by path (its name has hyphens)."""
    spec = importlib.util.spec_from_file_location("gate_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def summarize_ms(samples_s):
    ms = [s * 1000.0 for s in samples_s]
    return {
        "min": min(ms),
        "median": statistics.median(ms),
        "max": max(ms),
        "mean": statistics.fmean(ms),
    }


def bench_load_inventory(mod):
    load_inventory = mod.load_inventory
    # Warm the filesystem cache so we measure parse cost, not first-read I/O.
    table = load_inventory()
    rows = len(table)
    samples = []
    for _ in range(INVENTORY_ITERS):
        t0 = time.perf_counter()
        load_inventory()
        samples.append(time.perf_counter() - t0)
    return rows, summarize_ms(samples)


def make_event(command):
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode(
        "utf-8"
    )


def bench_gate(event_bytes, runs):
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        subprocess.run(
            [sys.executable, str(GATE)],
            input=event_bytes,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        samples.append(time.perf_counter() - t0)
    return summarize_ms(samples)


def fmt(stats):
    return (
        f"min {stats['min']:.3f} ms | "
        f"median {stats['median']:.3f} ms | "
        f"max {stats['max']:.3f} ms | "
        f"mean {stats['mean']:.3f} ms"
    )


def main():
    if not GATE.is_file():
        sys.stderr.write(f"gate not found: {GATE}\n")
        return 1

    print("=" * 70)
    print("Gate inventory-load benchmark")
    print("=" * 70)
    print(f"interpreter : {sys.executable}")
    print(f"gate        : {GATE}")
    print()

    # 1. In-process load_inventory() cost.
    mod = load_classifier()
    rows, inv = bench_load_inventory(mod)
    print(f"[1] load_inventory() x{INVENTORY_ITERS}  ({rows} rows parsed)")
    print(f"    {fmt(inv)}")
    print()

    # 2. End-to-end: full gate invocation on a stamped mutation vs a non-aws
    #    control that the gate early-exits before loading the inventory.
    e2e_aws = bench_gate(make_event(STAMPED_MUTATION), E2E_RUNS)
    e2e_ctrl = bench_gate(make_event(CONTROL_COMMAND), E2E_RUNS)
    added = e2e_aws["median"] - e2e_ctrl["median"]
    print(f"[2] full gate invocation x{E2E_RUNS}")
    print(f"    stamped mutation (aws path) : {fmt(e2e_aws)}")
    print(f"    non-aws control (early-exit): {fmt(e2e_ctrl)}")
    print(f"    added latency on aws path (median delta): {added:.3f} ms")
    print()

    # Verdict keyed on the in-process load cost -- the added work the aws path
    # does that the early-exit non-aws path does not. The end-to-end delta is
    # noisier (dominated by process startup jitter) but corroborates it.
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)
    per_cmd = inv["median"]
    print(f"median inventory-load cost per aws command : {per_cmd:.3f} ms")
    print(f"median end-to-end added latency (corroborates): {added:.3f} ms")
    print()
    THRESHOLD_MS = 30.0
    if per_cmd < THRESHOLD_MS:
        print(
            f"Under ~{THRESHOLD_MS:.0f} ms: NO INDEX WARRANTED. The early-exit already\n"
            "skips non-aws commands, so this cost is paid only on aws commands, where\n"
            "it is negligible against interpreter startup and the network round trip of\n"
            "the aws call itself. Keep the gate as-is."
        )
    else:
        print(
            f"At/above ~{THRESHOLD_MS:.0f} ms: an optimization would pay off. RECOMMENDATION\n"
            "(do NOT implement -- the gate is frozen this run): precompile the csv into a\n"
            "pickled dict (or an sqlite file) at build time via build-inventory.py, and have\n"
            "load_inventory() load the prebuilt artifact instead of re-parsing 17.8k csv rows\n"
            "on every invocation. Fall closed to the csv parse if the artifact is missing or\n"
            "stale so correctness never depends on the cache being present."
        )
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
