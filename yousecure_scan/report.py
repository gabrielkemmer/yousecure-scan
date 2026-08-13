from __future__ import annotations

from .ai_review import ReviewedFinding
from .scanner import Finding
from .url_scan import UrlFinding

SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def render_markdown(
    findings: list[Finding],
    reviewed: list[ReviewedFinding] | None = None,
    url_findings: list[UrlFinding] | None = None,
) -> str:
    lines = ["# yousecure-scan report", ""]

    if url_findings:
        lines.append(f"## Live site checks ({len(url_findings)} issue(s))")
        lines.append("")
        for u in url_findings:
            lines.append(f"- {SEVERITY_EMOJI.get(u.severity, '')} **{u.title}** — {u.detail}")
        lines.append("")

    if reviewed is not None:
        confirmed = [r for r in reviewed if r.verdict == "real"]
        lines.append(f"## Code checks: {len(confirmed)} confirmed issue(s) out of {len(findings)} pattern match(es) (AI-reviewed)")
        lines.append("")
        for r in confirmed:
            f = r.finding
            lines.append(f"### {SEVERITY_EMOJI.get(f.severity, '')} {f.title}")
            lines.append(f"- **File:** `{f.file}:{f.line}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Why:** {r.explanation}")
            lines.append(f"- **Fix:** {r.fix}")
            lines.append(f"- **Line:** `{f.snippet}`")
            lines.append("")
        return "\n".join(lines)

    if findings:
        lines.append(f"## Code checks: {len(findings)} pattern match(es) found (no AI review - set ANTHROPIC_API_KEY for that)")
        lines.append("")
        for f in findings:
            lines.append(f"### {SEVERITY_EMOJI.get(f.severity, '')} {f.title}")
            lines.append(f"- **File:** `{f.file}:{f.line}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Line:** `{f.snippet}`")
            lines.append("")

    return "\n".join(lines)
