#!/usr/bin/env python3
"""Check whether a read-only local wazuh-logtest command is available."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


COMMON_LOGTEST_PATHS = [
    "/var/ossec/bin/wazuh-logtest",
    "/var/ossec/bin/ossec-logtest",
]


def find_logtest(explicit_path: str | None = None) -> str | None:
    if explicit_path:
        return explicit_path if Path(explicit_path).exists() else None
    for name in ("wazuh-logtest", "ossec-logtest"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in COMMON_LOGTEST_PATHS:
        if Path(candidate).exists():
            return candidate
    return None


def check(explicit_path: str | None = None, timeout: int = 10) -> dict[str, Any]:
    path = find_logtest(explicit_path)
    if not path:
        return {
            "schema_version": "wazuh-capability-result-v0",
            "status": "unavailable",
            "proof_ceiling": "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY",
            "capability": "wazuh-logtest",
            "path": None,
            "message": "wazuh-logtest was not found; proof ceiling is unchanged.",
        }
    completed = subprocess.run([path, "-h"], text=True, capture_output=True, timeout=timeout, check=False)
    return {
        "schema_version": "wazuh-capability-result-v0",
        "status": "available" if completed.returncode in {0, 1} else "unknown",
        "proof_ceiling": "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY",
        "capability": "wazuh-logtest",
        "path": path,
        "returncode": completed.returncode,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--logtest-path")
    parser.add_argument("--allow-unavailable", action="store_true")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)
    result = check(args.logtest_path)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "available":
        return 0
    return 0 if args.allow_unavailable else 2


if __name__ == "__main__":
    raise SystemExit(main())
