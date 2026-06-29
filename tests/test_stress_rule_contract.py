from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stress_rule_contract


def test_stress_harness_rejects_all_mutations() -> None:
    result = stress_rule_contract.run_stress()
    assert result["status"] == "pass"
    assert result["mutations_run"] >= 11
    assert result["mutations_failed"] == 0
