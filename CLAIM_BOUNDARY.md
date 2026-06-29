# Claim Boundary

## Proof Ceiling

`SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY`

This repository can prove only deterministic validation of controlled local samples against a Wazuh-style rule contract.

## Allowed Claims

- The sample-level contract verifier passed for the included positive and negative fixtures.
- The positive fixture matched the contract.
- The negative fixture did not match the contract.
- The ProofCard was generated from controlled local verifier output.
- The Claim Firewall scanned public markdown and JSON artifacts for blocked wording.
- The repository is CI-checkable without private telemetry or a live Wazuh manager.

## Blocked Claims

- runtime active
- signal observed
- production ready
- enterprise validated
- SOC deployed
- autonomous SOC
- AI approved
- analyst approved
- public-safe runtime proof
- case closed
- live Wazuh proof
- customer deployed

These phrases are blocked as supported claims. They may appear in this section and other explicit boundary sections only to document what the repo refuses to claim.

## Private/Public Boundary

Public artifacts in this repo must contain only synthetic fixtures, documentation-safe placeholders, schemas, verifier output, and generated ProofCards. They must not contain private hostnames, private usernames, raw alerts, credentials, private IP addresses, customer references, or screenshots.

## Promotion Boundary

The current promotion path stops at sample-level validation. Any stronger claim would require a separate evidence gate, privacy review, stale review, wording review, and human approval before public wording changes.

## Reviewer Interpretation

Treat this repository as a reproducible claim-control lab. A green run means the local sample contract and claim firewall passed. It does not mean a live manager evaluated telemetry, a SOC deployed the rule, an analyst approved a case, or an AI system made a disposition.

