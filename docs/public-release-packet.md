# Public Release Packet

## Purpose

`wazuh-claim-furnace` is a public-safe hoxline-lab repository for sample-level Wazuh-style contract validation, claim-boundary enforcement, ProofCard generation, public-safety scanning, and optional controlled logtest bridge readiness.

## Proof Ceiling

Current ceiling: `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.

Optional future ceiling: `CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED` only after sanitized controlled `wazuh-logtest` execution succeeds.

## Validation Commands

```powershell
py -m pytest -q
py scripts\run_all.py
py scripts\verify_rule_contract.py --format json
py scripts\verify_claim_boundary.py --format json
py scripts\verify_public_safety.py --format json
py scripts\check_wazuh_capability.py --format json --allow-unavailable
py scripts\stress_rule_contract.py --format json
git diff --check
```

## Local Validation Status

Fill this from the final local run before public push. Do not infer status from commit history.

## Wazuh Capability Status

If `wazuh-logtest` is unavailable, record `WAZUH_RUNTIME_BRIDGE_NOT_EXECUTED` and keep the current ceiling.

## Safe Claims

- Sample-level Wazuh-style contract validation.
- Deterministic positive and negative fixture evaluation.
- Claim Firewall enforcement.
- Public-safety scan enforcement.
- ProofCard generation from controlled local outputs.
- Optional Wazuh logtest bridge readiness.

## Blocked Claims

blocked: runtime active, signal observed, production ready, enterprise validated, SOC deployed, autonomous SOC, AI approved, analyst approved, public-safe runtime proof, case closed, live Wazuh proof, and customer deployed.

## Reviewer Path

1. Read `CLAIM_BOUNDARY.md`.
2. Inspect `examples/ho-det-001/rule-contract.json`.
3. Run the validation commands.
4. Inspect `proofcards/ho-det-001-proofcard.md`.
5. Inspect `docs/evidence-capsule-model.md`.

## Final Public Push Requirements

- All validation commands pass.
- No private/public boundary violations exist.
- Branch is `main`.
- Remote, if created later, must be hoxline-lab scoped.
- No push happens without explicit approval.
