from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_rule_contract


def write_case(tmp_path: Path, contract: dict, positive: dict | None = None, negative: dict | None = None, expected: dict | None = None) -> Path:
    source_dir = verify_rule_contract.DEFAULT_CONTRACT.parent
    positive_data = positive if positive is not None else verify_rule_contract.load_json(source_dir / "event-positive.json")
    negative_data = negative if negative is not None else verify_rule_contract.load_json(source_dir / "event-negative.json")
    expected_data = expected if expected is not None else verify_rule_contract.load_json(source_dir / "expected-result.json")
    (tmp_path / "event-positive.json").write_text(json.dumps(positive_data), encoding="utf-8")
    (tmp_path / "event-negative.json").write_text(json.dumps(negative_data), encoding="utf-8")
    (tmp_path / "expected-result.json").write_text(json.dumps(expected_data), encoding="utf-8")
    contract_path = tmp_path / "rule-contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return contract_path


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


def test_expected_result_mismatch_fails(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    expected = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT.parent / "expected-result.json")
    expected["negative_sample"]["should_match"] = True
    with pytest.raises(verify_rule_contract.ContractError, match="negative expectation"):
        verify_rule_contract.verify_contract(write_case(tmp_path, contract, expected=expected))


def test_proof_ceiling_mismatch_fails(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    contract["proof_ceiling"] = "CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED"
    with pytest.raises(verify_rule_contract.ContractError, match="proof_ceiling"):
        verify_rule_contract.verify_contract(write_case(tmp_path, contract))


def test_missing_required_fixture_path_fails(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    contract["fixtures"]["positive"] = "missing-positive.json"
    with pytest.raises(verify_rule_contract.ContractError, match="missing file"):
        verify_rule_contract.verify_contract(write_case(tmp_path, contract))


def test_unsupported_operator_fails() -> None:
    event = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT.parent / "event-positive.json")
    condition = {"field": "data.win.system.eventID", "operator": "starts_with", "value": "1"}
    with pytest.raises(verify_rule_contract.ContractError, match="unsupported operator"):
        verify_rule_contract.evaluate_condition(event, condition)


def test_negative_sample_accidentally_matching_fails(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    positive = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT.parent / "event-positive.json")
    result = verify_rule_contract.verify_contract(write_case(tmp_path, contract, negative=positive))
    assert result["status"] == "fail"
    assert "negative sample did not match expected result" in result["what_failed"]


def test_temp_path_contract_outputs_display_paths_without_crashing(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    result = verify_rule_contract.verify_contract(write_case(tmp_path, contract))
    assert result["status"] == "pass"
    assert result["contract_path"].endswith("rule-contract.json")
    assert "test_temp_path_contract_output" in result["contract_path"]


def test_malformed_expected_result_schema_fails(tmp_path: Path) -> None:
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    expected = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT.parent / "expected-result.json")
    expected.pop("positive_sample")
    with pytest.raises(verify_rule_contract.ContractError, match="expected result schema validation failed"):
        verify_rule_contract.verify_contract(write_case(tmp_path, contract, expected=expected))
