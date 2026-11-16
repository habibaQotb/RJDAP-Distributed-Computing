# RJDAP-1: Reliable Job Dispatch & Aggregation Protocol (Phase 1)

CSE361 Computer Networks, Fall 2026, Project 2.
A UDP-only protocol that distributes stateless compute tasks (find the nonce whose
SHA-256 matches a target digest) from a Command Hub to a pool of workers, with
heartbeats, timeout-based reassignment and exactly-once result registration.

Team: Habiba Ahmed Kotb, Amira Botros Enaam, Mennatallah Emad, Salma Ahmed Belal, Sarah Ayman Anwar

## Demo video (5 minutes)

VIDEO LINK: <PASTE YOUR LINK HERE>   (access: "anyone with the link can view")

## Repository layout

    src/hub.py                  Command Hub (server)
    src/worker.py               Compute node (client)
    scripts/run_baseline.py     Automated 'Baseline (LAN)' test (cross-platform)
    scripts/run_baseline.sh     Wrapper for Linux / macOS / WSL
    captures/baseline.pcapng    Wireshark capture of the Baseline scenario
    docs/RFC.pdf                Mini-RFC draft
    results/                    Created automatically; one folder per run

## Requirements

- Python 3.8 or newer. No third-party packages (standard library only).
- Works on Linux, macOS and Windows.

## Quick start: automated Baseline test

From the repository root:

    python scripts/run_baseline.py          # Windows / any OS
    ./scripts/run_baseline.sh               # Linux / macOS / WSL

This starts the hub (1,000 tasks) and 4 workers on localhost, waits for completion
and prints PASS/FAIL. Expected result (typical run, about 1 second):

    [PASS] all 1000 tasks completed (1000/1000)
    [PASS] zero reassignments (reassigned_task_count = 0)
    [PASS] zero duplicate results (duplicate_results_dropped = 0)
    OVERALL: PASS

Options: `--port 9999 --tasks 1000 --workers 4 --seed 1`

Logs are saved in `results/baseline_<timestamp>_seed<seed>/`:
`hub_stdout.txt`, `worker<N>_stdout.txt`, `hub_packets.csv`, `worker<N>_packets.csv`,
`summary.txt`.

## Manual run (5 terminals)

    # Terminal 1: hub
    python src/hub.py --port 9999 --tasks 1000 --min-workers 4 --seed 1

    # Terminals 2-5: one worker each
    python src/worker.py --server 127.0.0.1 --port 9999

The hub waits until 4 workers have joined, then starts dispatching. It prints
its metrics when all tasks are done.

## Metrics printed by the hub

`total_completion_time`, `reassigned_task_count`, `duplicate_results_dropped`,
`worker_idle_time_ms` (per worker).

## Baseline scenario (netem)

Baseline uses no impairment, so no `tc` command is needed. For later scenarios
(Linux only, replace `<IF>` with `lo` for localhost):

    sudo tc qdisc add dev <IF> root netem loss 10%        # Severe Loss
    sudo tc qdisc add dev <IF> root netem delay 150ms     # Delayed ACKs
    sudo tc qdisc del dev <IF> root                       # remove

Worker crash test: run a worker with `--crash-after N` or kill it manually.