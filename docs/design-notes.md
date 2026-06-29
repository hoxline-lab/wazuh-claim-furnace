# Design Notes

The lab uses a Python-first shape because the core problem is contract validation, not service orchestration.

The rule contract is intentionally small:

- metadata identifies the candidate and proof ceiling;
- required event fields make sample shape explicit;
- match conditions describe deterministic expectations;
- fixture paths bind the contract to a positive and negative sample;
- blocked claims keep wording constraints close to the evidence.

The verifier does not call `wazuh-logtest` and does not inspect any live Wazuh manager. It evaluates JSON samples only. The term "Wazuh-style" is used because the contract models a rule-validation boundary without claiming runtime integration.

The Claim Firewall scans public markdown and JSON surfaces. Python source is not scanned as public copy because implementation files need test phrases and constants. Tests exercise that scanner directly.

