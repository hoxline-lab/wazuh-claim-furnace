# wazuh-claim-furnace

`wazuh-claim-furnace` is a hoxline-lab experiment for testing one narrow security-engineering contract: a Wazuh-style rule candidate can be evaluated against controlled positive and negative samples, rendered into a ProofCard, and checked by a Claim Firewall before anyone is allowed to say more than the evidence supports.

This repository is not a Wazuh manager, not a detection deployment, and not a proof portal. It is a small furnace for claim discipline: feed it a contract, fixtures, and allowed wording; it returns deterministic validation output and rejects unsafe claims.

## What It Proves

- A sample-level Wazuh-style rule contract is structurally valid.
- The positive fixture matches the contract.
- The negative fixture does not match the contract.
- The ProofCard can be regenerated from verifier output.
- The Claim Firewall catches blocked wording outside allowed boundary sections.
- CI can reproduce those checks without private systems.

Proof ceiling: `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.

## What It Does Not Prove

This lab does not prove runtime active status, signal observed status, production ready status, enterprise validated coverage, SOC deployed status, public-safe runtime proof, live Wazuh proof, customer deployed status, analyst approved disposition, AI approved disposition, or case closed authority.

Those phrases are intentionally blocked unless they appear in explicit boundary sections that explain they are not supported.

## Why hoxline-lab

`hoxline-lab` is the right authority for this repository because the repo is an experimental, public-safe validation harness. It is not claiming production authority, private telemetry, live manager state, SOC deployment, or analyst approval. The lab can borrow structural discipline from prior proof and validation work, but its evidence boundary is self-contained here.

## Run Locally

```powershell
python --version
python -m pip install -U pip
python -m pip install pytest jsonschema
python scripts/run_all.py
python -m pytest -q
```

The primary verifier also supports direct JSON output:

```powershell
python scripts/verify_rule_contract.py --format json
```

## CI Contract

`.github/workflows/claim-furnace.yml` runs on `push` and `pull_request` with least-privilege `contents: read`. It installs only Python test dependencies, runs the test suite, then runs `scripts/run_all.py`.

CI passing means the static/sample-level contract and claim boundary checks passed. It does not raise the proof ceiling.

## Claim Firewall

`scripts/verify_claim_boundary.py` scans public markdown and JSON files for forbidden phrases. The V0 scanner allows blocked terms only when the surrounding section or JSON path is explicitly a boundary, blocked-claim, not-tested, or "does not prove" context.

The firewall is intentionally conservative. If public copy needs stronger wording, the correct move is to change evidence and promotion gates first, not to loosen the sentence.

## Reviewer Path

Start with:

- `examples/ho-det-001/rule-contract.json`
- `scripts/verify_rule_contract.py`
- `proofcards/ho-det-001-proofcard.md`
- `CLAIM_BOUNDARY.md`
- `docs/reviewer-guide.md`

The sample data is documentation-safe and synthetic. It uses placeholders such as `HOST-001`, `USER-001`, `192.0.2.10`, `2001:db8::10`, and `C:\Users\USER-001\`.
