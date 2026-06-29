# Threat Model

## What This Repo Defends Against

- Overclaiming sample validation as runtime proof.
- Treating a generated ProofCard as authority beyond its inputs.
- Accidentally publishing private data, private event payload content, or secret-like material.
- Letting Wazuh bridge availability inflate the proof ceiling without controlled execution.
- CI drift where tests pass but claim-boundary or public-safety checks are skipped.

## Primary Controls

- Deterministic positive and negative fixtures.
- JSON Schema validation for contract and expected-result shape.
- Mutation harness for negative control coverage.
- Claim Firewall for blocked public wording.
- Public-safety scanner for private ranges, identity paths, raw alert markers, and secret-like assignments.
- Wazuh bridge states that separate unavailable, available-not-executed, and controlled sample validation.

## Non-Goals

blocked: runtime active status, signal observed status, production ready status, SOC deployed status, public-safe runtime proof, analyst approval, AI disposition authority, customer deployment, enterprise validation, and case closure.
