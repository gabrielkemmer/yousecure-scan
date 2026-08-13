"""Optional second pass: send each pattern-matched finding to Claude to
confirm it's a real issue (not a false positive) and get a concrete fix.

Needs ANTHROPIC_API_KEY set. Skipped entirely if the key isn't present or
the `anthropic` package isn't installed - the plain pattern scan in
scanner.py works standalone without this.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .scanner import Finding

DEFAULT_MODEL = os.environ.get("YOUSECURE_SCAN_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = """\
You are a security code reviewer. You'll be shown one automated finding \
(a suspicious line matched by a regex rule) along with a few lines of \
surrounding context. Decide if it's a real security issue or a false \
positive, and if real, give a one-sentence fix.

Respond in exactly this format, nothing else:
VERDICT: real|false_positive
EXPLANATION: <one sentence>
FIX: <one sentence, or "n/a" if false_positive>
"""


@dataclass
class ReviewedFinding:
    finding: Finding
    verdict: str
    explanation: str
    fix: str


def _context_snippet(root: str, finding: Finding, radius: int = 3) -> str:
    path = os.path.join(root, finding.file)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return finding.snippet

    start = max(0, finding.line - 1 - radius)
    end = min(len(lines), finding.line + radius)
    return "".join(lines[start:end])


def review(root: str, findings: list[Finding], model: str = DEFAULT_MODEL) -> list[ReviewedFinding]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set - AI review requires it")

    import anthropic  # local import: keep this an optional dependency

    client = anthropic.Anthropic(api_key=api_key)
    reviewed: list[ReviewedFinding] = []

    for finding in findings:
        context = _context_snippet(root, finding)
        user_msg = (
            f"Rule: {finding.title} ({finding.rule_id})\n"
            f"File: {finding.file}:{finding.line}\n"
            f"Context:\n{context}"
        )
        response = client.messages.create(
            model=model,
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")

        verdict, explanation, fix = "real", text.strip(), "n/a"
        for line in text.splitlines():
            if line.startswith("VERDICT:"):
                verdict = line.split(":", 1)[1].strip()
            elif line.startswith("EXPLANATION:"):
                explanation = line.split(":", 1)[1].strip()
            elif line.startswith("FIX:"):
                fix = line.split(":", 1)[1].strip()

        reviewed.append(ReviewedFinding(finding=finding, verdict=verdict, explanation=explanation, fix=fix))

    return reviewed
