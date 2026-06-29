#!/usr/bin/env python3
"""Validate a Wazuh-style sample rule contract against local fixtures."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised only in missing dependency environments.
    jsonschema = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "examples" / "ho-det-001" / "rule-contract.json"
PROOF_CEILING = "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY"
CONTRACT_SCHEMA = ROOT / "schemas" / "rule-contract-v0.schema.json"
EXPECTED_RESULT_SCHEMA = ROOT / "schemas" / "expected-result-v0.schema.json"
REQUIRED_CONTRACT_FIELDS = [
    "schema_version",
    "candidate_id",
    "title",
    "engine_family",
    "proof_ceiling",
    "required_fields",
    "match",
    "fixtures",
    "expected",
    "safe_claims",
    "blocked_claims",
]


class ContractError(ValueError):
    """Raised when a contract or fixture is invalid."""


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON in {path}: {exc}") from exc


def validate_json_schema(instance: Any, schema_path: Path, label: str) -> None:
    if jsonschema is None:
        raise ContractError("jsonschema is required for schema-backed validation")
    schema = load_json(schema_path)
    try:
        jsonschema.Draft202012Validator(schema).validate(instance)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(part) for part in exc.path) or "<root>"
        raise ContractError(f"{label} schema validation failed at {location}: {exc.message}") from exc


def get_path(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(dotted_path)
        current = current[part]
    return current


def missing_required_event_fields(event: dict[str, Any], fields: list[str]) -> list[str]:
    missing: list[str] = []
    for field in fields:
        try:
            get_path(event, field)
        except KeyError:
            missing.append(field)
    return missing


def validate_contract_shape(contract: dict[str, Any]) -> None:
    missing = [field for field in REQUIRED_CONTRACT_FIELDS if field not in contract]
    if missing:
        raise ContractError(f"missing required contract fields: {', '.join(missing)}")
    if contract["schema_version"] != "rule-contract-v0":
        raise ContractError("schema_version must be rule-contract-v0")
    if contract["engine_family"] != "wazuh-style-json-sample":
        raise ContractError("engine_family must be wazuh-style-json-sample")
    if contract["proof_ceiling"] != PROOF_CEILING:
        raise ContractError(f"proof_ceiling must be {PROOF_CEILING}")
    if not isinstance(contract["required_fields"], list) or not contract["required_fields"]:
        raise ContractError("required_fields must be a non-empty list")
    if "all" not in contract["match"] or not isinstance(contract["match"]["all"], list):
        raise ContractError("match.all must be a list")
    for name in ("positive", "negative"):
        if name not in contract["fixtures"]:
            raise ContractError(f"fixtures.{name} is required")
    if "expected_result" not in contract["fixtures"]:
        raise ContractError("fixtures.expected_result is required")


def evaluate_condition(event: dict[str, Any], condition: dict[str, Any]) -> bool:
    field = condition.get("field")
    operator = condition.get("operator")
    if not isinstance(field, str) or not isinstance(operator, str):
        raise ContractError("each match condition requires field and operator")
    try:
        raw_value = get_path(event, field)
    except KeyError:
        return False
    value = str(raw_value)
    if operator == "equals":
        return value == str(condition.get("value"))
    if operator == "contains":
        return str(condition.get("value")) in value
    if operator == "contains_ci":
        return str(condition.get("value", "")).lower() in value.lower()
    if operator == "contains_any_ci":
        values = condition.get("values")
        if not isinstance(values, list) or not values:
            raise ContractError("contains_any_ci requires a non-empty values list")
        lowered = value.lower()
        return any(str(item).lower() in lowered for item in values)
    if operator == "regex":
        return re.search(str(condition.get("value", "")), value) is not None
    raise ContractError(f"unsupported operator: {operator}")


def event_matches(event: dict[str, Any], contract: dict[str, Any]) -> bool:
    return all(evaluate_condition(event, condition) for condition in contract["match"]["all"])


def verify_contract(contract_path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    contract_path = contract_path.resolve()
    contract = load_json(contract_path)
    if not isinstance(contract, dict):
        raise ContractError("contract must be a JSON object")
    validate_json_schema(contract, CONTRACT_SCHEMA, "rule contract")
    validate_contract_shape(contract)

    sample_dir = contract_path.parent
    positive_path = sample_dir / contract["fixtures"]["positive"]
    negative_path = sample_dir / contract["fixtures"]["negative"]
    expected_result_path = sample_dir / contract["fixtures"]["expected_result"]
    positive = load_json(positive_path)
    negative = load_json(negative_path)
    expected_result = load_json(expected_result_path)
    if not isinstance(positive, dict) or not isinstance(negative, dict):
        raise ContractError("fixtures must be JSON objects")
    if not isinstance(expected_result, dict):
        raise ContractError("expected result must be a JSON object")
    validate_json_schema(expected_result, EXPECTED_RESULT_SCHEMA, "expected result")
    if expected_result.get("candidate_id") != contract["candidate_id"]:
        raise ContractError("expected result candidate_id does not match contract")
    if expected_result.get("proof_ceiling") != contract["proof_ceiling"]:
        raise ContractError("expected result proof_ceiling does not match contract")

    fixture_missing = {
        "positive": missing_required_event_fields(positive, contract["required_fields"]),
        "negative": missing_required_event_fields(negative, contract["required_fields"]),
    }
    if fixture_missing["positive"] or fixture_missing["negative"]:
        raise ContractError(f"fixture required field failure: {fixture_missing}")

    positive_matches = event_matches(positive, contract)
    negative_matches = event_matches(negative, contract)
    expected_positive = bool(contract["expected"]["positive_matches"])
    expected_negative = bool(contract["expected"]["negative_matches"])
    if bool(expected_result.get("positive_sample", {}).get("should_match")) != expected_positive:
        raise ContractError("expected-result positive expectation does not match contract")
    if bool(expected_result.get("negative_sample", {}).get("should_match")) != expected_negative:
        raise ContractError("expected-result negative expectation does not match contract")
    failures: list[str] = []
    if positive_matches != expected_positive:
        failures.append("positive sample did not match expected result")
    if negative_matches != expected_negative:
        failures.append("negative sample did not match expected result")

    status = "pass" if not failures else "fail"
    return {
        "schema_version": "rule-contract-result-v0",
        "status": status,
        "candidate_id": contract["candidate_id"],
        "proof_ceiling": contract["proof_ceiling"],
        "schema_validation": "pass",
        "contract_path": display_path(contract_path),
        "sample_set": display_path(sample_dir),
        "expected_result_path": display_path(expected_result_path),
        "positive": {
            "path": display_path(positive_path),
            "matched": positive_matches,
            "expected": expected_positive,
        },
        "negative": {
            "path": display_path(negative_path),
            "matched": negative_matches,
            "expected": expected_negative,
        },
        "what_passed": [
            "Contract required fields were present.",
            "Positive sample matched.",
            "Negative sample did not match.",
        ]
        if status == "pass"
        else [],
        "what_failed": failures,
        "safe_claims": contract["safe_claims"],
        "blocked_claims": contract["blocked_claims"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)
    try:
        result = verify_contract(args.contract)
    except ContractError as exc:
        result = {"schema_version": "rule-contract-result-v0", "status": "fail", "error": str(exc)}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
