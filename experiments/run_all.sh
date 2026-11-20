#!/usr/bin/env bash
# Regenerates every CSV in results/ (about 10-20 minutes on a laptop-class CPU).
set -euo pipefail
cd "$(dirname "$0")"
python3 run_correctness.py
python3 run_timing.py
python3 run_protocol.py
python3 run_analytic.py
