#!/usr/bin/env python3
"""Run a sanitized sample through wazuh-logtest when explicitly available."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import check_wazuh_capability


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SAMPLE = ROOT / "examples" / "ho-det-001" / "event-positive.json"
UPGRADED_CEILING = "CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED"
BASE_CEILING = "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY"


def run_sample(sample: Path, logtest_path: str | None, timeout: int = 20) -> dict[str, Any]:
    path = check_wazuh_capability.find_logtest(logtest_path)
    if not path:
        return {
            "schema_version": "wazuh-logtest-sample-result-v0",
            "status": "unavailable",
            "proof_ceiling": BASE_CEILING,
            "sample": sample.relative_to(ROOT).as_posix() if sample.is_relative_to(ROOT) else sample.as_posix(),
            "message": "wazuh-logtest was not found; no logtest proof was created.",
        }
    sample_text = sample.read_text(encoding="utf-8")
    completed = subprocess.run(
        [path],
        input=sample_text + "\n",
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    status = "pass" if completed.returncode == 0 else "fail"
    return {
        "schema_version": "wazuh-logtest-sample-result-v0",
        "status": status,
        "proof_ceiling": UPGRADED_CEILING if status == "pass" else BASE_CEILING,
        "sample": sample.relative_to(ROOT).as_posix() if sample.is_relative_to(ROOT) else sample.as_posix(),
        "logtest_path": path,
        "returncode": completed.returncode,
        "stdout_sha256_available_in_private_evidence_only": bool(completed.stdout),
        "stderr_present": bool(completed.stderr),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--logtest-path")
    parser.add_argument("--allow-unavailable", action="store_true")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)
    result = run_sample(args.sample, args.logtest_path)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "pass":
        return 0
    if result["status"] == "unavailable" and args.allow_unavailable:
        return 0
    return 2 if result["status"] == "unavailable" else 1


if __name__ == "__main__":
    raise SystemExit(main())
