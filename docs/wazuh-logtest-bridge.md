# Wazuh Logtest Bridge

## Purpose

`wazuh-logtest` is useful for checking how Wazuh parsing and rules evaluate a supplied event. In this lab, it is an optional bridge from static sample-contract validation to controlled local Wazuh sample evaluation.

## Why Optional

Public CI should not require a live Wazuh manager or private lab system. Many reviewers will not have Wazuh installed. The repository therefore treats logtest as a capability check and controlled next step, not as a baseline requirement.

## What It Can Prove

If sanitized controlled sample execution succeeds, the proof ceiling may become:

`CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED`

That means a controlled sample was evaluated by a Wazuh logtest command under bounded conditions.

## What It Cannot Prove

Logtest success does not prove runtime active status, signal observed status, production ready status, SOC deployed status, public-safe runtime proof, analyst approved disposition, AI approved disposition, customer deployed status, or case closed authority.

It is still a controlled sample check, not a live telemetry or response claim.

## Public/Private Boundary

The public repo stores sanitized sample events, contracts, scripts, and docs only. Private evidence or local run notes, if needed, belong under:

`C:\Raylee\Data\Hoxline\wazuh-claim-furnace`

Do not copy raw alerts, private hostnames, private usernames, internal IPs, credentials, screenshots, or server details into this repository.

## Safe Execution Model

- Discover capability with `scripts/check_wazuh_capability.py`.
- Execute only sanitized samples.
- Do not edit Wazuh config, rules, or decoders.
- Do not restart services.
- Do not export raw alerts.
- Emit machine-readable JSON.
- Keep the proof ceiling unchanged unless controlled logtest execution succeeds.

## Bridge States

| State | Meaning | Ceiling |
|---|---|---|
| `unavailable` | No usable logtest command was found. | `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY` |
| `available_not_executed` | A logtest command appears present, but no sanitized sample was executed. | `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY` |
| `controlled_logtest_sample_validated` | A sanitized sample was evaluated successfully by logtest. | `CONTROLLED_WAZUH_LOGTEST_SAMPLE_VALIDATED` for that artifact only |

blocked: runtime active status, signal observed status, production ready status, SOC deployed status, public-safe runtime proof, analyst approval, AI disposition authority, customer deployment, enterprise validation, and case closure.
