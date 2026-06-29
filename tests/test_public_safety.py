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


def test_private_term_scanner_catches_json_yaml_and_env_secret_forms() -> None:
    text = '"access_token": "abcdefghijklmnop"\nrefresh_token: abcdefghijklmnop\nPRIVATE_KEY=abcdefghijklmnop\n'
    findings = verify_public_safety.scan_text(Path("sample.md"), text)
    assert [finding["rule"] for finding in findings] == [
        "secret_assignment",
        "secret_assignment",
        "secret_assignment",
    ]


def test_public_safety_allows_documentation_placeholders() -> None:
    text = "HOST-001 USER-001 192.0.2.10 2001:db8::10 C:\\Users\\USER-001\\\n"
    assert verify_public_safety.scan_text(Path("sample.md"), text) == []


def test_public_safety_catches_personal_windows_user_and_private_key() -> None:
    text = "C:\\Users\\RealUser\\Desktop\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
    findings = verify_public_safety.scan_text(Path("sample.md"), text)
    assert {finding["rule"] for finding in findings} == {"personal_windows_user", "ssh_private_key"}
