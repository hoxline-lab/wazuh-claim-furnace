from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_claim_boundary


def test_forbidden_claim_scanner_catches_unsafe_wording(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.md"
    unsafe.write_text("# Bad\n\nThis lab is production ready.\n", encoding="utf-8")
    findings = verify_claim_boundary.scan_markdown(unsafe, unsafe.read_text(encoding="utf-8"))
    assert findings
    assert findings[0]["phrase"] == "production ready"


def test_forbidden_claim_allowed_in_blocked_section(tmp_path: Path) -> None:
    safe = tmp_path / "safe.md"
    safe.write_text("# Boundary\n\n## Blocked Claims\n\n- production ready\n", encoding="utf-8")
    findings = verify_claim_boundary.scan_markdown(safe, safe.read_text(encoding="utf-8"))
    assert findings == []

