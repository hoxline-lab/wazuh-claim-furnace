from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_proofcard
import verify_claim_boundary


def test_proofcard_generation_includes_proof_ceiling(tmp_path: Path) -> None:
    output = tmp_path / "proofcard.md"
    generate_proofcard.generate(output)
    text = output.read_text(encoding="utf-8")
    assert "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY" in text
    assert "What Was Not Tested" in text


def test_generated_proofcard_passes_claim_boundary_scan(tmp_path: Path) -> None:
    output = tmp_path / "proofcard.md"
    generate_proofcard.generate(output)
    findings = verify_claim_boundary.scan_markdown(output, output.read_text(encoding="utf-8"))
    assert findings == []
