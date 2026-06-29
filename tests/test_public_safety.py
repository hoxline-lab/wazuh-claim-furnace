from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_public_safety


def test_private_term_scanner_catches_private_ip() -> None:
    findings = verify_public_safety.scan_text(Path("sample.md"), "host = 10.1.2.3\n")
    assert findings
    assert findings[0]["rule"] == "private_ipv4_10"


def test_private_term_scanner_catches_secret_like_key() -> None:
    findings = verify_public_safety.scan_text(Path("sample.md"), "service_token = abcdefghijklmnop\n")
    assert findings
    assert findings[0]["rule"] == "secret_assignment"


def test_public_safety_allows_documentation_placeholders() -> None:
    text = "HOST-001 USER-001 192.0.2.10 2001:db8::10 C:\\Users\\USER-001\\\n"
    assert verify_public_safety.scan_text(Path("sample.md"), text) == []

