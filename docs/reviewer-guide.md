# Reviewer Guide

## 60-Second Path

1. Open `CLAIM_BOUNDARY.md` and confirm the proof ceiling is `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.
2. Open `examples/ho-det-001/rule-contract.json` and inspect the contract fields.
3. Run `py scripts\run_all.py`.
4. Open `proofcards/ho-det-001-proofcard.md` and verify the card repeats the same ceiling.
5. Open `docs/wazuh-logtest-bridge.md` and confirm the optional bridge does not create runtime proof.

## Inspect First

- `scripts/verify_rule_contract.py` for deterministic fixture evaluation.
- `scripts/verify_claim_boundary.py` for blocked wording enforcement.
- `scripts/verify_public_safety.py` for private-data and secret-pattern scanning.
- `scripts/stress_rule_contract.py` for deterministic negative mutation coverage.
- `scripts/generate_proofcard.py` for generated reviewer output.
- `scripts/check_wazuh_capability.py` for optional local logtest capability discovery.
- `.github/workflows/claim-furnace.yml` for CI scope.

## Reproduce Validation

```powershell
py -m pip install pytest jsonschema
py scripts\run_all.py
py scripts\stress_rule_contract.py --format json
py -m pytest -q
```

The verifier emits JSON so reviewers can inspect the exact match decision and fixture paths.

## Optional Next Proof Step

If a reviewer has a safe local Wazuh tooling environment, run:

```powershell
py scripts\check_wazuh_capability.py --format json
```

Only run `scripts\run_wazuh_logtest_sample.py` against sanitized samples and only when the command path is known. The result can support a controlled logtest sample claim, not live runtime proof.

## Interpret The ProofCard

The ProofCard is a route card generated from local verifier output. It is useful for review because it gathers what passed, what failed, what was not tested, safe claims, blocked claims, and the proof ceiling in one place.

## Evidence Capsule

Open `docs/evidence-capsule-model.md` and `examples/evidence-capsule/sample-controlled-validation-capsule.json` to see how source truth, validation truth, Wazuh logtest truth, runtime truth, signal truth, and public proof remain separate.

## What Not To Infer

Do not infer runtime active status, signal observed status, public-safe runtime proof, production ready status, SOC deployed status, customer deployed status, analyst approved disposition, AI approved disposition, or case closed authority from this lab.
