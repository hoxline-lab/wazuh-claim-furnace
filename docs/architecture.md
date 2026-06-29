# Architecture

## Flow

`fixtures -> rule contract -> schema validation -> deterministic verifier -> mutation harness -> ProofCard -> Claim Firewall -> public-safety scan -> optional Wazuh bridge`

## Components

- `examples/ho-det-001/`: sanitized sample set and expected result.
- `schemas/`: machine-readable contracts for rule, expected-result, ProofCard, and evidence capsule.
- `scripts/verify_rule_contract.py`: validates schema, fixture presence, required event fields, and match expectations.
- `scripts/stress_rule_contract.py`: proves negative controls fail closed.
- `scripts/generate_proofcard.py`: renders a reviewer-facing ProofCard from verifier output and gate status.
- `scripts/verify_claim_boundary.py`: blocks unsupported public wording outside explicit boundary contexts.
- `scripts/verify_public_safety.py`: blocks private data and secret-like material.
- `scripts/check_wazuh_capability.py`: detects local logtest capability without requiring execution.
- `scripts/run_wazuh_logtest_sample.py`: optional controlled sample execution path.

## Authority Boundary

The architecture is evidence-routed, not assertion-routed. A component can report only what it measured. The default ceiling remains `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`.
