#!/usr/bin/env bash
# RJDAP-1 Baseline (LAN) scenario - Linux/macOS/WSL wrapper.
# Usage: ./scripts/run_baseline.sh
set -e
cd "$(dirname "$0")/.."
exec python3 scripts/run_baseline.py "$@"
