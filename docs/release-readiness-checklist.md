# Release Readiness Checklist

## Required Before Public Push

- `py -m pytest -q` passes.
- `py scripts\run_all.py` passes.
- `py scripts\verify_claim_boundary.py --format json` returns `status: pass`.
- `py scripts\verify_public_safety.py --format json` returns `status: pass`.
- `git diff --check` returns clean.
- `git status --short` contains only intended changes before commit and is clean after commit.
- No remote points to a non-hoxline-lab identity.

## Reviewer Meaning

Passing checks mean the public repo is reproducible at the stated ceiling. They do not prove runtime active status, signal observed status, production ready status, SOC deployed status, public-safe runtime proof, analyst approval, AI disposition authority, or case closure.

## Optional Bridge

Wazuh logtest bridge execution is optional. If it is not run, record `WAZUH_RUNTIME_BRIDGE_NOT_EXECUTED` and keep the proof ceiling at `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.

