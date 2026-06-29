#!/usr/bin/env python3
"""Scan public repo files for private data and secret-like material."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SUFFIXES = {".md", ".json", ".yml", ".yaml"}
EXCLUDED_DIRS = {".git", ".pytest_cache", "__pycache__"}
ALLOWED_SECTION_MARKERS = (
    "blocked claims",
    "what it does not prove",
    "what this does not prove",
    "what not to infer",
    "what was not tested",
)
ALLOWED_JSON_PATH_PARTS = (
    "blocked_claims",
    "what_was_not_tested",
)
ALLOWED_LITERALS = {
    "HOST-001",
    "USER-001",
    "192.0.2.10",
    "2001:db8::10",
    r"C:\Users\USER-001",
    r"C:\\Users\\USER-001",
}
LINE_ALLOW_MARKERS = (
    "must not contain",
    "are allowed",
    "documentation-safe placeholders",
    "scan public repo surfaces for",
    "private ranges",
    "secret-like",
    "raw alert markers",
    "ssh private key material",
    "do not copy",
    "do not export",
    "forbidden",
    "no private telemetry",
    "does not prove",
    "do not infer",
    "blocked",
    "not tested",
)


PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_ipv4_10", re.compile(r"\b10(?:\.\d{1,3}){3}\b")),
    ("private_ipv4_172", re.compile(r"\b172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}\b")),
    ("private_ipv4_192_168", re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b")),
    ("personal_windows_user", re.compile(r"C:\\Users\\(?!USER-001\\)[A-Za-z0-9._-]+", re.IGNORECASE)),
    ("mufg_reference", re.compile(r"\bMUFG\b", re.IGNORECASE)),
    ("raw_alert_marker", re.compile(r"\b(?:raw alert|full_log|predecoder|rule\.id|agent\.id)\b", re.IGNORECASE)),
    ("customer_reference", re.compile(r"\bcustomer(?:s|'s)?\b", re.IGNORECASE)),
    ("private_hostname_hint", re.compile(r"\b(?:corp|internal|prod|dc|srv|wazuh-manager)[A-Za-z0-9._-]*(?:\d|[._-])[A-Za-z0-9._-]*\b", re.IGNORECASE)),
    ("ssh_private_key", re.compile(r"BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY", re.IGNORECASE)),
    ("secret_assignment", re.compile(r"\b(?:api[_-]?key|password|token|secret|credential)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}", re.IGNORECASE)),
]


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def public_files(root: Path = ROOT) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in PUBLIC_SUFFIXES:
            yield path


def line_allowed(line: str) -> bool:
    lower = line.lower()
    if any(marker in lower for marker in LINE_ALLOW_MARKERS):
        return True
    return any(literal in line for literal in ALLOWED_LITERALS)


def scan_text(path: Path, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line_allowed(line):
            continue
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if match.group(0) in ALLOWED_LITERALS:
                    continue
                findings.append(
                    {
                        "path": display_path(path),
                        "line": line_number,
                        "rule": name,
                        "match": match.group(0),
                    }
                )
    return findings


def markdown_section(line: str, current: str) -> str:
    match = re.match(r"^#+\s+(.*)$", line.strip())
    if match:
        return match.group(1).strip().lower()
    return current


def scan_markdown(path: Path, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    section = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        section = markdown_section(line, section)
        if any(marker in section for marker in ALLOWED_SECTION_MARKERS) or line_allowed(line):
            continue
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if match.group(0) in ALLOWED_LITERALS:
                    continue
                findings.append(
                    {
                        "path": display_path(path),
                        "line": line_number,
                        "rule": name,
                        "match": match.group(0),
                    }
                )
    return findings


def iter_json_strings(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from iter_json_strings(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_json_strings(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def scan_json(path: Path, text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [{"path": display_path(path), "line": 0, "rule": "invalid_json", "match": str(exc)}]
    findings: list[dict[str, Any]] = []
    for field_path, value in iter_json_strings(data):
        if any(part in field_path.lower() for part in ALLOWED_JSON_PATH_PARTS) or line_allowed(value):
            continue
        findings.extend(scan_text(path, value))
    return findings


def scan_file(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".md":
        return scan_markdown(path, text)
    if path.suffix.lower() == ".json":
        return scan_json(path, text)
    return scan_text(path, text)


def scan(root: Path = ROOT) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    for path in public_files(root):
        scanned.append(display_path(path))
        findings.extend(scan_file(path))
    return {
        "schema_version": "public-safety-result-v0",
        "status": "pass" if not findings else "fail",
        "proof_ceiling": "SAMPLE_LEVEL_WAZUH_CONTRACT_VALIDATION_ONLY",
        "files_scanned": scanned,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args(argv)
    result = scan()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
