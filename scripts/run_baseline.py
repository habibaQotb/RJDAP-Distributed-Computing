#!/usr/bin/env python3
"""
RJDAP-1 'Baseline (LAN)' test scenario - automated runner (Phase 1).

What it does
  1. Starts the Command Hub (src/hub.py) with 1,000 tasks, waiting for 4 workers.
  2. Starts 4 compute nodes (src/worker.py) on localhost.
  3. Waits for the hub to finish, then reads its summary.
  4. Checks the acceptance criteria and prints PASS / FAIL:
        - 1,000 / 1,000 tasks completed
        - zero duplicate executions   (reassigned_task_count == 0 and
                                       duplicate_results_dropped == 0)
  5. Saves hub/worker stdout and per-packet CSV logs in
        results/baseline_<timestamp>_seed<seed>/

No netem is applied (baseline = no impairment). Works on Linux, macOS, Windows.
Standard library only.

Usage (from the repository root):
    python scripts/run_baseline.py
    python scripts/run_baseline.py --seed 7 --port 9999 --tasks 1000 --workers 4
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HUB = os.path.join(ROOT, "src", "hub.py")
WORKER = os.path.join(ROOT, "src", "worker.py")


def parse_args():
    p = argparse.ArgumentParser(description="RJDAP-1 Baseline (LAN) test")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--tasks", type=int, default=1000)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--seed", type=int, default=1, help="deterministic seed for the hub")
    p.add_argument("--timeout", type=float, default=120.0,
                   help="give up after this many seconds")
    p.add_argument("--outdir", default=os.path.join(ROOT, "results"))
    return p.parse_args()


def grab(pattern, text, cast=float, default=None):
    m = re.search(pattern, text)
    return cast(m.group(1)) if m else default


def main():
    args = parse_args()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(args.outdir, f"baseline_{stamp}_seed{args.seed}")
    os.makedirs(run_dir, exist_ok=True)

    print(f"[baseline] output folder: {run_dir}")
    print(f"[baseline] {args.workers} workers, {args.tasks} tasks, "
          f"port {args.port}, seed {args.seed}, no netem")

    hub_out = open(os.path.join(run_dir, "hub_stdout.txt"), "w")
    hub = subprocess.Popen(
        [sys.executable, HUB, "--port", str(args.port), "--tasks", str(args.tasks),
         "--min-workers", str(args.workers), "--seed", str(args.seed),
         "--log", os.path.join(run_dir, "hub_packets.csv")],
        stdout=hub_out, stderr=subprocess.STDOUT, cwd=ROOT)
    time.sleep(0.5)                                   # let the hub bind its socket

    workers, worker_outs = [], []
    for i in range(1, args.workers + 1):
        f = open(os.path.join(run_dir, f"worker{i}_stdout.txt"), "w")
        worker_outs.append(f)
        workers.append(subprocess.Popen(
            [sys.executable, WORKER, "--server", "127.0.0.1", "--port", str(args.port),
             "--log", os.path.join(run_dir, f"worker{i}_packets.csv")],
            stdout=f, stderr=subprocess.STDOUT, cwd=ROOT))

    t_start = time.monotonic()
    timed_out = False
    try:
        hub.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        hub.kill()
    except KeyboardInterrupt:
        hub.kill()
        timed_out = True

    # workers exit by themselves a few seconds after the hub goes silent
    for w in workers:
        try:
            w.wait(timeout=15)
        except subprocess.TimeoutExpired:
            w.kill()
    for f in [hub_out] + worker_outs:
        f.close()
    wall = time.monotonic() - t_start

    with open(os.path.join(run_dir, "hub_stdout.txt")) as f:
        text = f.read()

    done = grab(r"tasks done: (\d+)/", text, int, 0)
    total_t = grab(r"total_completion_time: ([\d.]+)", text, float, 0.0)
    reassigned = grab(r"reassigned_task_count: (\d+)", text, int, -1)
    dups = grab(r"duplicate_results_dropped: (\d+)", text, int, -1)
    idle = re.findall(r"worker (\d+) worker_idle_time_ms: ([\d.]+)", text)

    checks = [
        (f"all {args.tasks} tasks completed ({done}/{args.tasks})", done == args.tasks),
        (f"zero reassignments (reassigned_task_count = {reassigned})", reassigned == 0),
        (f"zero duplicate results (duplicate_results_dropped = {dups})", dups == 0),
        ("run finished without timeout", not timed_out),
    ]

    lines = ["", "=" * 60, "BASELINE (LAN) RESULT", "=" * 60,
             f"total_completion_time : {total_t:.3f} s",
             f"reassigned_task_count : {reassigned}",
             f"duplicate_results_dropped : {dups}"]
    for wid, ms in idle:
        lines.append(f"worker {wid} worker_idle_time_ms : {ms}")
    lines.append("-" * 60)
    ok = True
    for label, passed in checks:
        lines.append(f"[{'PASS' if passed else 'FAIL'}] {label}")
        ok &= passed
    lines += ["-" * 60, f"OVERALL: {'PASS' if ok else 'FAIL'}", ""]
    report = "\n".join(lines)
    print(report)
    with open(os.path.join(run_dir, "summary.txt"), "w") as f:
        f.write(report)

    print(f"[baseline] logs saved in {run_dir}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
