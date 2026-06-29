# Future Orbit Visual Layer

`hoxline-orbit` should sit downstream of verifier output, not upstream of claim authority.

The visual layer can show a chain:

`claim -> evidence -> validation -> ProofCard -> Claim Firewall decision`

Visuals must not create authority. A chart, node graph, badge, animation, or website page can make review easier, but it cannot raise the proof ceiling or turn a blocked claim into a supported one.

Useful future views:

- contract match path for each fixture;
- blocked-claim decision trace;
- ProofCard generation provenance;
- CI run summary;
- promotion gate checklist.

The visual layer should preserve `SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY` unless a later evidence process explicitly changes the ceiling.

