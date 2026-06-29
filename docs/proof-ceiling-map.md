# Proof Ceiling Map

| Ceiling | Evidence Required | Safe Claim | Blocked Even Then |
|---|---|---|---|
| `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY` | Contract, fixtures, expected result, local verifier, ProofCard, Claim Firewall, public-safety scan | Controlled sample contract validation passed | blocked: runtime, signal, production, SOC deployment, public-safe runtime proof, analyst approval, AI disposition authority |
| `CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED` | Successful sanitized sample execution through `wazuh-logtest` with machine-readable result | Controlled Wazuh logtest sample validation passed | blocked: live runtime detection, signal observation, production readiness, SOC deployment, case closure |

The visual or reviewer surface may route evidence, but it cannot raise a proof ceiling. Only evidence and approved wording can do that.
