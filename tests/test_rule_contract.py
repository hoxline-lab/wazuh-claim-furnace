from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_rule_contract


def test_positive_sample_matches() -> None:
    result = verify_rule_contract.verify_contract()
    assert result["positive"]["matched"] is True
    assert result["status"] == "pass"


def test_negative_sample_does_not_match() -> None:
    result = verify_rule_contract.verify_contract()
    assert result["negative"]["matched"] is False
    assert result["status"] == "pass"


def test_missing_required_contract_field_fails() -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    broken = copy.deepcopy(contract)
    broken.pop("proof_ceiling")
    with pytest.raises(verify_rule_contract.ContractError):
        verify_rule_contract.validate_contract_shape(broken)

