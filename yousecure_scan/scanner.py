"""Walks a directory tree and runs every rule against every matching file."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .rules import RULES

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".tox", "vendor", "target",
}
DEFAULT_MAX_FILE_BYTES = 2_000_000  # skip huge/binary-ish files


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str


def _iter_files(root: str, skip_dirs: set[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for name in filenames:
            yield os.path.join(dirpath, name)


def scan(root: str, skip_dirs: set[str] | None = None) -> list[Finding]:
    skip_dirs = skip_dirs or DEFAULT_SKIP_DIRS
    findings: list[Finding] = []

    for path in _iter_files(root, skip_dirs):
        try:
            if os.path.getsize(path) > DEFAULT_MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        ext = os.path.splitext(path)[1]
        applicable = [r for r in RULES if not r.languages or ext in r.languages]
        if not applicable:
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue

        text = "".join(lines)
        for rule in applicable:
            for match in rule.pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        file=os.path.relpath(path, root),
                        line=line_no,
                        snippet=snippet[:200],
                    )
                )

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_rank.get(f.severity, 9), f.file, f.line))
    return findings
