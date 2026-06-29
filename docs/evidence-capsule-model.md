# Evidence Capsule Model

The evidence capsule is a public-safe map of truth planes. It prevents a source artifact or validation result from being mistaken for runtime or signal proof.

## Truth Planes

- `source_truth`: the contract and sanitized sample files exist.
- `validation_truth`: deterministic local verification result.
- `wazuh_logtest_truth`: optional controlled logtest sample result.
- `runtime_truth`: blocked unless separate runtime evidence exists.
- `signal_truth`: blocked unless separate signal evidence exists.
- `public_proof`: the exact public proof ceiling and public-safe boundary.

Current sample capsule: `examples/evidence-capsule/sample-controlled-validation-capsule.json`.

The current capsule populates source and validation truth only. blocked: runtime, signal, public-safe runtime proof, production readiness, SOC deployment, analyst approval, AI disposition authority, case closure, customer deployment, and enterprise validation.
