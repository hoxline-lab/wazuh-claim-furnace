from __future__ import annotations

import sys


from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_wazuh_capability
import run_wazuh_logtest_sample


def test_logtest_unavailable_does_not_inflate_proof_ceiling() -> None:
    result = check_wazuh_capability.check("Z:/definitely/not/wazuh-logtest")
    assert result["status"] == "unavailable"
    assert result["proof_ceiling"] == "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY"


def test_logtest_sample_unavailable_returns_clean_status() -> None:
    sample = ROOT / "examples" / "ho-det-001" / "event-positive.json"
    result = run_wazuh_logtest_sample.run_sample(sample, "Z:/definitely/not/wazuh-logtest")
    assert result["status"] == "unavailable"
    assert result["proof_ceiling"] == "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY"
