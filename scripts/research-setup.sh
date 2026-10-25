#!/usr/bin/env bash
set -euo pipefail
task_research_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_research_root"
python3 -m venv .tools/research-venv
.tools/research-venv/bin/python -m pip install -r research/requirements-research.txt
.tools/research-venv/bin/python research/upstream_tools.py --fetch
.tools/research-venv/bin/python research/fetch_reference_copies.py --fetch
