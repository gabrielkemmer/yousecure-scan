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
    parser.add_argument("path", nargs="?", default=None, help="Directory to scan (default: current directory, skipped if --url is given alone)")
    parser.add_argument("--url", help="Also scan a live site for exposed .env/.git, missing security headers, wildcard CORS, etc. - use this for a vibecoded app/site you don't have the source for")
    parser.add_argument("--ai-review", action="store_true", help="Send each code finding to Claude to confirm real issues and suggest fixes (needs ANTHROPIC_API_KEY)")
    parser.add_argument("-o", "--output", help="Write the Markdown report to this file instead of stdout")
    args = parser.parse_args()

    if args.path is None and args.url is None:
        args.path = "."

    url_findings = []
    if args.url:
        from .url_scan import scan_url

        url_findings = scan_url(args.url)

    findings = []
    root = None
    if args.path:
        root = os.path.abspath(args.path)
        findings = scan(root)

    if not findings and not url_findings:
        print("No issues found.")
        return

    reviewed = None
    if args.ai_review and findings:
        from .ai_review import review

        try:
            reviewed = review(root, findings)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)

    report = render_markdown(findings, reviewed, url_findings)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
