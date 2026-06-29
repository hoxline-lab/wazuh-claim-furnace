# wazuh-claim-furnace

`wazuh-claim-furnace` is a measurable Wazuh claim-control lab: static contract validation, public-safety scanning, ProofCard generation, and an optional read-only `wazuh-logtest` bridge without runtime overclaiming.

It is not a Wazuh manager, not a deployment package, and not a proof portal. Feed it a contract, fixtures, and public wording; it returns deterministic validation output, rejects unsafe claims, and keeps every stronger claim behind an evidence gate.

## Proof Ceiling

| State | Meaning |
|---|---|
| Current ceiling | `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY` |
| Optional next ceiling | `CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED` only if sanitized controlled `wazuh-logtest` execution succeeds |
| Still blocked after logtest | blocked: runtime, signal, production, SOC deployment, public-safe runtime proof, analyst approval, AI disposition authority, case closure |

## What It Proves Now

- The sample-level Wazuh-style rule contract is structurally valid.
- The positive fixture matches the contract.
- The negative fixture does not match the contract.
- `expected-result.json` agrees with contract expectations.
- The ProofCard can be regenerated from verifier output.
- The Claim Firewall catches blocked wording outside allowed boundary sections.
- The public-safety scanner rejects private ranges, secret-like material, raw alert markers, and private identity terms.
- The stress harness rejects deterministic negative mutations.
- CI can reproduce those checks without private systems.

## What It Does Not Prove

This lab does not prove runtime active status, signal observed status, production ready status, enterprise validated coverage, SOC deployed status, public-safe runtime proof, live Wazuh proof, customer deployed status, analyst approved disposition, AI approved disposition, or case closed authority.

Those phrases are intentionally blocked unless they appear in explicit boundary sections that explain they are not supported.

## Why hoxline-lab

`hoxline-lab` is the right authority for this repository because the repo is an experimental, public-safe validation harness. It is not claiming production authority, private telemetry, live manager state, SOC deployment, or analyst approval. The lab can borrow structural discipline from prior proof and validation work, but its evidence boundary is self-contained here.

## Run Locally

```powershell
py --version
py -m pip install -U pip
py -m pip install pytest jsonschema
py scripts\run_all.py
py -m pytest -q
```

The primary verifier also supports direct JSON output:

```powershell
py scripts\verify_rule_contract.py --format json
py scripts\verify_claim_boundary.py --format json
py scripts\verify_public_safety.py --format json
```

Use `python` instead of `py` on systems where Python is installed that way.

## CI Contract

`.github/workflows/claim-furnace.yml` runs on `push` and `pull_request` with least-privilege `contents: read`. It installs only Python test dependencies, runs the test suite, then runs `scripts/run_all.py`.

CI passing means the static/sample-level contract and claim boundary checks passed. It does not raise the proof ceiling.

## Claim Firewall

`scripts/verify_claim_boundary.py` scans public markdown and JSON files for forbidden phrases. The V0 scanner allows blocked terms only when the surrounding section or JSON path is explicitly a boundary, blocked-claim, not-tested, or "does not prove" context.

The firewall is intentionally conservative. If public copy needs stronger wording, the correct move is to change evidence and promotion gates first, not to loosen the sentence.

## Public Safety Gate

`scripts/verify_public_safety.py` scans public repo surfaces for private IP ranges, secret-like keys, personal Windows user paths, raw alert markers, private host hints, customer references, and SSH private key material.

Documentation-safe placeholders are allowed: `HOST-001`, `USER-001`, `192.0.2.10`, `2001:db8::10`, and `C:\Users\USER-001\`.

## Optional Wazuh Logtest Bridge

`docs/wazuh-logtest-bridge.md` describes the bridge. `scripts/check_wazuh_capability.py` can identify whether a local `wazuh-logtest` binary is available. `scripts/run_wazuh_logtest_sample.py` can execute a sanitized sample only when a logtest path is explicitly supplied or discoverable.

Bridge states are `unavailable`, `available_not_executed`, and `controlled_logtest_sample_validated`. If the bridge is unavailable, the repo reports a skipped/unavailable status and keeps the proof ceiling at `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`. A successful controlled logtest run would support only `CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED`; blocked: runtime, signal, production, and public-safe runtime proof.

## V0.1 Stress Pass

- Added public-safety scanning.
- Added optional Wazuh logtest bridge design and scripts.
- Strengthened failure-mode tests for expectation drift, ceiling drift, missing fixtures, unsupported operators, negative matches, and generated ProofCard scanning.
- Added reviewer readiness docs and a proof-ceiling map.
- Kept runtime and signal claims blocked.

## Reviewer Path

Start with:

- `examples/ho-det-001/rule-contract.json`
- `scripts/verify_rule_contract.py`
- `proofcards/ho-det-001-proofcard.md`
- `CLAIM_BOUNDARY.md`
- `docs/reviewer-guide.md`
- `docs/release-readiness-checklist.md`
- `docs/proof-ceiling-map.md`
- `docs/wazuh-logtest-bridge.md`
- `docs/evidence-capsule-model.md`
- `docs/threat-model.md`
- `docs/architecture.md`
- `docs/public-release-packet.md`

The sample data is documentation-safe and synthetic. It uses placeholders such as `HOST-001`, `USER-001`, `192.0.2.10`, `2001:db8::10`, and `C:\Users\USER-001\`.
