# cve_watch.py

Daily job: checks for newly published CVEs relevant to what yousecure-scan
covers, asks Gemini whether any warrant a new detection rule, and opens a
**pull request** (never pushes straight to `master`) with the proposed
rule for human review. Sends a WhatsApp notification when a PR is opened.

## Why a PR, not a direct commit

The whole pitch of this tool is "trustworthy security checks." An
unreviewed, AI-drafted regex landing directly on `master` without a human
looking at it first is the exact failure mode a security tool should not
have. The automation here does the tedious part (watching CVE feeds daily,
drafting a first pass) - a human still merges.

## Setup

```bash
export OPENROUTER_API_KEY=...     # calls google/gemini-2.5-flash through OpenRouter
export GITHUB_TOKEN=...           # fine-grained PAT, Contents+PRs write on this repo only, used by `gh`
export YOUSECURE_SCAN_REPO=owner/yousecure-scan
export NOTIFY_WHATSAPP_NUMBER=5521...   # optional
```

No extra Python dependencies - the OpenRouter call goes through the
standard library (`urllib`), same as the rest of this project.

Needs `git` and the `gh` CLI (authenticated) on PATH.

## Cron

```
0 7 * * * cd /path/to/yousecure-scan && /usr/bin/python3 scripts/cve_watch.py >> /var/log/yousecure-scan-cve-watch.log 2>&1
```

State (which CVE IDs have already been processed) lives in
`cve_watch_state.json` next to this script - safe to re-run, it's a no-op
unless there's something new.
