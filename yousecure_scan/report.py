from __future__ import annotations

from .ai_review import ReviewedFinding
from .scanner import Finding

SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def render_markdown(findings: list[Finding], reviewed: list[ReviewedFinding] | None = None) -> str:
    lines = ["# yousecure-scan report", ""]

    if reviewed is not None:
        confirmed = [r for r in reviewed if r.verdict == "real"]
        lines.append(f"{len(confirmed)} confirmed issue(s) out of {len(findings)} pattern match(es) (AI-reviewed).")
        lines.append("")
        for r in confirmed:
            f = r.finding
            lines.append(f"## {SEVERITY_EMOJI.get(f.severity, '')} {f.title}")
            lines.append(f"- **File:** `{f.file}:{f.line}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Why:** {r.explanation}")
            lines.append(f"- **Fix:** {r.fix}")
            lines.append(f"- **Line:** `{f.snippet}`")
            lines.append("")
        return "\n".join(lines)

    lines.append(f"{len(findings)} pattern match(es) found (no AI review - set ANTHROPIC_API_KEY for that).")
    lines.append("")
    for f in findings:
        lines.append(f"## {SEVERITY_EMOJI.get(f.severity, '')} {f.title}")
        lines.append(f"- **File:** `{f.file}:{f.line}`")
        lines.append(f"- **Rule:** `{f.rule_id}`")
        lines.append(f"- **Line:** `{f.snippet}`")
        lines.append("")
    return "\n".join(lines)
