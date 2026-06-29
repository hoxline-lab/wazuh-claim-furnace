# Reviewer Guide

## 60-Second Path

1. Open `CLAIM_BOUNDARY.md` and confirm the proof ceiling is `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.
2. Open `examples/ho-det-001/rule-contract.json` and inspect the contract fields.
3. Run `python scripts/run_all.py`.
4. Open `proofcards/ho-det-001-proofcard.md` and verify the card repeats the same ceiling.

## Inspect First

- `scripts/verify_rule_contract.py` for deterministic fixture evaluation.
- `scripts/verify_claim_boundary.py` for blocked wording enforcement.
- `scripts/generate_proofcard.py` for generated reviewer output.
- `.github/workflows/claim-furnace.yml` for CI scope.

## Reproduce Validation

```powershell
python -m pip install pytest jsonschema
python scripts/run_all.py
python -m pytest -q
```

The verifier emits JSON so reviewers can inspect the exact match decision and fixture paths.

## Interpret The ProofCard

The ProofCard is a route card generated from local verifier output. It is useful for review because it gathers what passed, what failed, what was not tested, safe claims, blocked claims, and the proof ceiling in one place.

## What Not To Infer

Do not infer runtime active status, signal observed status, public-safe runtime proof, production ready status, SOC deployed status, customer deployed status, analyst approved disposition, AI approved disposition, or case closed authority from this lab.

