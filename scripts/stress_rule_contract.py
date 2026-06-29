#!/usr/bin/env python3
"""Run deterministic negative mutations against the sample contract."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path
from typing import Any, Callable

import verify_claim_boundary
import verify_public_safety
import verify_rule_contract


ROOT = Path(__file__).resolve().parents[1]
PROOF_CEILING = "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY"
LOCAL_TMP = ROOT / "test-tmp" / "stress"


def load_base() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    sample_dir = verify_rule_contract.DEFAULT_CONTRACT.parent
    contract = verify_rule_contract.load_json(verify_rule_contract.DEFAULT_CONTRACT)
    positive = verify_rule_contract.load_json(sample_dir / "event-positive.json")
    negative = verify_rule_contract.load_json(sample_dir / "event-negative.json")
    expected = verify_rule_contract.load_json(sample_dir / "expected-result.json")
    return contract, positive, negative, expected


def write_case(root: Path, contract: dict[str, Any], positive: dict[str, Any], negative: dict[str, Any], expected: dict[str, Any]) -> Path:
    (root / "event-positive.json").write_text(json.dumps(positive, indent=2), encoding="utf-8")
    (root / "event-negative.json").write_text(json.dumps(negative, indent=2), encoding="utf-8")
    (root / "expected-result.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")
    contract_path = root / "rule-contract.json"
    contract_path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    return contract_path


def expect_exception(contract: dict[str, Any], positive: dict[str, Any], negative: dict[str, Any], expected: dict[str, Any]) -> bool:
    LOCAL_TMP.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=LOCAL_TMP) as tmp:
        contract_path = write_case(Path(tmp), contract, positive, negative, expected)
        try:
            verify_rule_contract.verify_contract(contract_path)
        except verify_rule_contract.ContractError:
            return True
    return False


def expect_fail_status(contract: dict[str, Any], positive: dict[str, Any], negative: dict[str, Any], expected: dict[str, Any]) -> bool:
    LOCAL_TMP.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=LOCAL_TMP) as tmp:
        contract_path = write_case(Path(tmp), contract, positive, negative, expected)
        result = verify_rule_contract.verify_contract(contract_path)
    return result["status"] == "fail"


def mutation_missing_proof_ceiling() -> bool:
    contract, positive, negative, expected = load_base()
    contract.pop("proof_ceiling")
    return expect_exception(contract, positive, negative, expected)


def mutation_wrong_proof_ceiling() -> bool:
    contract, positive, negative, expected = load_base()
    contract["proof_ceiling"] = "CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED"
    return expect_exception(contract, positive, negative, expected)


def mutation_missing_positive_fixture() -> bool:
    contract, positive, negative, expected = load_base()
    contract["fixtures"]["positive"] = "missing-positive.json"
    return expect_exception(contract, positive, negative, expected)


def mutation_missing_negative_fixture() -> bool:
    contract, positive, negative, expected = load_base()
    contract["fixtures"]["negative"] = "missing-negative.json"
    return expect_exception(contract, positive, negative, expected)


def mutation_missing_expected_result_fixture() -> bool:
    contract, positive, negative, expected = load_base()
    contract["fixtures"]["expected_result"] = "missing-expected.json"
    return expect_exception(contract, positive, negative, expected)


def mutation_unsupported_operator() -> bool:
    contract, positive, negative, expected = load_base()
    contract["match"]["all"][0]["operator"] = "starts_with"
    return expect_exception(contract, positive, negative, expected)


def mutation_positive_should_not_match() -> bool:
    contract, positive, negative, expected = load_base()
    contract["match"]["all"][2]["values"] = ["-definitely-not-present"]
    return expect_fail_status(contract, positive, negative, expected)


def mutation_negative_accidentally_matches() -> bool:
    contract, positive, _negative, expected = load_base()
    return expect_fail_status(contract, positive, positive, expected)


def mutation_expected_result_drift() -> bool:
    contract, positive, negative, expected = load_base()
    expected["negative_sample"]["should_match"] = True
    return expect_exception(contract, positive, negative, expected)


def mutation_unsafe_claim_injection() -> bool:
    findings = verify_claim_boundary.scan_markdown(Path("README.md"), "# Claim\n\nThis is live Wazuh proof.\n")
    return bool(findings)


def mutation_private_value_injection() -> bool:
    findings = verify_public_safety.scan_text(Path("sample.md"), "service_token = abcdefghijklmnop\nhost=10.1.2.3\n")
    return len(findings) >= 2


MUTATIONS: list[tuple[str, Callable[[], bool]]] = [
    ("missing_proof_ceiling", mutation_missing_proof_ceiling),
    ("wrong_proof_ceiling", mutation_wrong_proof_ceiling),
    ("missing_positive_fixture", mutation_missing_positive_fixture),
    ("missing_negative_fixture", mutation_missing_negative_fixture),
    ("missing_expected_result_fixture", mutation_missing_expected_result_fixture),
    ("unsupported_operator", mutation_unsupported_operator),
    ("positive_should_not_match", mutation_positive_should_not_match),
    ("negative_accidentally_matches", mutation_negative_accidentally_matches),
    ("expected_result_drift", mutation_expected_result_drift),
    ("unsafe_claim_injection", mutation_unsafe_claim_injection),
    ("private_value_injection", mutation_private_value_injection),
]


def run_stress() -> dict[str, Any]:
    failures: list[dict[str, str]] = []
    for name, mutation in MUTATIONS:
        try:
            passed = mutation()
        except Exception as exc:  # noqa: BLE001 - mutation failure is reported as data.
            failures.append({"mutation": name, "error": str(exc)})
            continue
        if not passed:
            failures.append({"mutation": name, "error": "mutation was not rejected"})
    return {
        "schema_version": "rule-contract-stress-result-v0",
        "status": "pass" if not failures else "fail",
        "mutations_run": len(MUTATIONS),
        "mutations_passed": len(MUTATIONS) - len(failures),
        "mutations_failed": len(failures),
        "proof_ceiling": PROOF_CEILING,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)
    result = run_stress()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
