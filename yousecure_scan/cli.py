from __future__ import annotations

import argparse
import os
import sys

from .report import render_markdown
from .scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="yousecure-scan",
        description="Fast, pattern-based security scanner with an optional Claude-powered review pass.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")
    parser.add_argument("--ai-review", action="store_true", help="Send each finding to Claude to confirm real issues and suggest fixes (needs ANTHROPIC_API_KEY)")
    parser.add_argument("-o", "--output", help="Write the Markdown report to this file instead of stdout")
    args = parser.parse_args()

    root = os.path.abspath(args.path)
    findings = scan(root)

    if not findings:
        print("No issues found by the pattern scan.")
        return

    reviewed = None
    if args.ai_review:
        from .ai_review import review

        try:
            reviewed = review(root, findings)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)

    report = render_markdown(findings, reviewed)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
