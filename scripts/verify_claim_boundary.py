#!/usr/bin/env python3
"""Scan public markdown and JSON files for blocked claim wording."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]


def display_path(path: Path) -> str:
    """Return repo-relative paths for repo files and safe paths for external test files."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


BLOCKED_PHRASES = [
    "runtime active",
    "signal observed",
    "production ready",
    "enterprise validated",
    "SOC deployed",
    "autonomous SOC",
    "AI approved",
    "analyst approved",
    "public-safe runtime proof",
    "case closed",
    "live Wazuh proof",
    "customer deployed",
]
ALLOWED_SECTION_MARKERS = (
    "blocked claims",
    "what it does not prove",
    "what this does not prove",
    "what not to infer",
    "what was not tested",
    "promotion boundary",
    "reviewer interpretation",
    "reviewer interpretation guide",
    "claim firewall",
)
ALLOWED_LINE_MARKERS = (
    "does not prove",
    "do not prove",
    "do not infer",
    "not tested",
    "not supported",
    "blocked",
    "refuses to claim",
    "must not",
)
ALLOWED_JSON_PATH_PARTS = (
    "blocked_claims",
    "what_was_not_tested",
    "not_tested",
    "blocked",
)
EXCLUDED_DIRS = {".git", ".pytest_cache", "__pycache__", "test-tmp", ".pytest_tmp"}


def public_files(root: Path = ROOT) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in {".md", ".json"}:
            yield path


def markdown_section(line: str, current: str) -> str:
    match = re.match(r"^#+\s+(.*)$", line.strip())
    if match:
        return match.group(1).strip().lower()
    return current


def markdown_context_allowed(section: str, line: str) -> bool:
    lower = line.lower()
    if any(marker in section for marker in ALLOWED_SECTION_MARKERS):
        return True
    return any(marker in lower for marker in ALLOWED_LINE_MARKERS)


def scan_markdown(path: Path, text: str) -> list[dict[str, Any]]:
    section = ""
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        section = markdown_section(line, section)
        lower = line.lower()
        for phrase in BLOCKED_PHRASES:
            if phrase.lower() in lower and not markdown_context_allowed(section, line):
                findings.append(
                    {
                        "path": display_path(path),
                        "line": line_number,
                        "phrase": phrase,
                        "section": section,
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


def json_context_allowed(path: str, value: str) -> bool:
    lower_path = path.lower()
    lower_value = value.lower()
    if any(part in lower_path for part in ALLOWED_JSON_PATH_PARTS):
        return True
    return any(marker in lower_value for marker in ALLOWED_LINE_MARKERS)


def scan_json(path: Path, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [{"path": display_path(path), "error": f"invalid JSON: {exc}"}]
    for field_path, value in iter_json_strings(data):
        lower = value.lower()
        for phrase in BLOCKED_PHRASES:
            if phrase.lower() in lower and not json_context_allowed(field_path, value):
                findings.append(
                    {
                        "path": display_path(path),
                        "json_path": field_path,
                        "phrase": phrase,
                    }
                )
    return findings


def scan_file(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".md":
        return scan_markdown(path, text)
    if path.suffix.lower() == ".json":
        return scan_json(path, text)
    return []


def scan(root: Path = ROOT) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned: list[str] = []
    for path in public_files(root):
        scanned.append(display_path(path))
        findings.extend(scan_file(path))
    return {
        "schema_version": "claim-boundary-result-v0",
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

