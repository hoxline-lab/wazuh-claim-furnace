#!/usr/bin/env python3
"""Run the local claim-furnace validation suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_step(name: str, command: list[str]) -> int:
    print(f"== {name} ==")
    completed = subprocess.run(command, cwd=ROOT, text=True)
    if completed.returncode != 0:
        print(f"FAIL: {name}", file=sys.stderr)
    return completed.returncode


def main() -> int:
    steps = [
        ("rule contract verifier", [sys.executable, "scripts/verify_rule_contract.py", "--format", "json"]),
        ("proofcard generator", [sys.executable, "scripts/generate_proofcard.py"]),
        ("claim boundary verifier", [sys.executable, "scripts/verify_claim_boundary.py", "--format", "json"]),
        ("public safety verifier", [sys.executable, "scripts/verify_public_safety.py", "--format", "json"]),
        ("wazuh capability check", [sys.executable, "scripts/check_wazuh_capability.py", "--format", "json", "--allow-unavailable"]),
        ("pytest", [sys.executable, "-m", "pytest", "-q"]),
    ]
    for name, command in steps:
        code = run_step(name, command)
        if code != 0:
            return code
    print("STATUS=pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

