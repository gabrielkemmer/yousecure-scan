"""Daily CVE watch: pulls recently published CVEs relevant to this scanner's
coverage (Python/JS/Node/Django/Flask/Supabase/Firebase/JWT/etc.), asks
Gemini whether any of them justify a new detection rule, and - if so -
opens a pull request with the proposed rule for human review.

Deliberately does NOT push straight to main. An unreviewed, AI-generated
regex landing directly in a public security tool is exactly the kind of
mistake this project exists to catch in other people's code - a PR review
step (which also runs this repo's own CI, once configured) is cheap
insurance against that. A WhatsApp notification is sent so nothing sits
waiting for a review nobody knew to do.

Run via cron (see README in this scripts/ dir). State (which CVEs have
already been processed) is kept in cve_watch_state.json next to this
script, so re-running is a no-op unless there's something new.

Required env vars: OPENROUTER_API_KEY (calls Gemini via OpenRouter),
GITHUB_TOKEN (fine-grained, Contents+PRs write on this repo only),
YOUSECURE_SCAN_REPO ("owner/repo"), NOTIFY_WHATSAPP_NUMBER (optional).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
STATE_FILE = SCRIPT_DIR / "cve_watch_state.json"
RULES_FILE = REPO_ROOT / "yousecure_scan" / "rules.py"

# Keyword filter on the CVE's own description - keeps this to CVEs plausibly
# relevant to what yousecure-scan actually looks at (web app / app-layer
# code patterns), not the full unfiltered NVD firehose (~40/day, mostly
# hardware/OS/kernel and irrelevant here).
RELEVANT_KEYWORDS = [
    "django", "flask", "fastapi", "express.js", "next.js", "supabase",
    "firebase", "jwt", "json web token", "deserialization", "pickle",
    "sql injection", "cross-site scripting", "server-side request forgery",
    "ssrf", "prototype pollution", "path traversal", "command injection",
    "cors", "authentication bypass",
]

OPENROUTER_MODEL = "google/gemini-2.5-flash"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"processed_cve_ids": []}


def _save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def fetch_recent_cves(days: int = 1) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "yousecure-scan-cve-watch"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        if not text:
            continue
        if any(kw in text.lower() for kw in RELEVANT_KEYWORDS):
            cves.append({"id": cve_id, "description": text})
    return cves


def ask_gemini_for_rule(cve: dict, current_rules_source: str) -> dict | None:
    """Returns {"rule_code": "...", "rationale": "..."} or None if Gemini
    decides no new rule is warranted (e.g. too CVE-specific, not a
    generalizable pattern, or already covered).

    Calls Gemini through OpenRouter (OpenAI-compatible /chat/completions),
    not the Gemini SDK directly - OPENROUTER_API_KEY is an OpenRouter key,
    not a Google AI Studio one."""
    prompt = f"""\
You maintain the rule set for a regex-based security scanner (yousecure-scan).
Here is the current rules.py content:

---
{current_rules_source}
---

Here is a newly published CVE:
ID: {cve['id']}
Description: {cve['description']}

Decide: does this CVE represent a *generalizable* code pattern our scanner
could plausibly catch with a new regex `Rule(...)` entry (in the same style
as the existing ones)? Most CVEs won't - they're specific to one library's
internal bug, not a pattern a project's own code would reproduce. Only
propose a rule if it's genuinely generalizable (e.g. "don't disable cert
validation", not "upgrade libfoo to 1.2.4").

Respond with EXACTLY one of:
1) The single line "NO_RULE_WARRANTED" if nothing generalizable applies.
2) A valid Python `Rule(...)` entry (matching the existing dataclass fields
   and style) that could be appended to the RULES list, followed on a new
   line by "RATIONALE: <one sentence>".
"""
    body = json.dumps({
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        payload = json.loads(resp.read())
    text = payload["choices"][0]["message"]["content"].strip()

    if text == "NO_RULE_WARRANTED" or "NO_RULE_WARRANTED" in text.splitlines()[0]:
        return None

    if "RATIONALE:" not in text:
        return None  # malformed response - fail closed, no auto-generated rule without a rationale

    rule_code, _, rationale = text.rpartition("RATIONALE:")
    return {"rule_code": rule_code.strip(), "rationale": rationale.strip()}


def open_pr_for_rule(cve: dict, proposal: dict) -> str:
    branch = f"cve-watch/{cve['id'].lower()}"
    subprocess.run(["git", "-C", str(REPO_ROOT), "checkout", "-b", branch], check=True)

    # Append the proposed rule just before the closing `]` of RULES.
    source = RULES_FILE.read_text()
    marker = "\n]\n\n# Filenames"
    if marker not in source:
        marker = "\n]"
    insertion = f"    {proposal['rule_code']}\n" + marker
    RULES_FILE.write_text(source.replace(marker, insertion, 1))

    subprocess.run(["git", "-C", str(REPO_ROOT), "add", str(RULES_FILE)], check=True)
    commit_msg = f"Propose rule for {cve['id']} (auto-drafted, needs review)\n\n{proposal['rationale']}"
    subprocess.run(["git", "-C", str(REPO_ROOT), "commit", "-m", commit_msg], check=True)
    subprocess.run(["git", "-C", str(REPO_ROOT), "push", "-u", "origin", branch], check=True)

    result = subprocess.run(
        [
            "gh", "pr", "create",
            "--repo", os.environ["YOUSECURE_SCAN_REPO"],
            "--title", f"cve-watch: possible new rule for {cve['id']}",
            "--body", f"Auto-drafted by cve_watch.py from a Gemini review of {cve['id']}.\n\n"
                      f"**This is unreviewed AI-generated output - read the regex carefully before merging.**\n\n"
                      f"CVE description: {cve['description']}\n\nRationale: {proposal['rationale']}",
            "--head", branch,
        ],
        check=True, capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    return result.stdout.strip()


def notify(message: str) -> None:
    number = os.environ.get("NOTIFY_WHATSAPP_NUMBER")
    if not number:
        print(message)
        return
    sys.path.insert(0, str(REPO_ROOT.parent / "host_yousecure" / "vision_agents" / "runtime"))
    try:
        import agent_runtime
        agent_runtime.send_whatsapp_message(number, message)
    except Exception as exc:  # noqa: BLE001 - notification failure shouldn't crash the whole run
        print(f"WhatsApp notify failed ({exc}); message was: {message}")


def main() -> None:
    state = _load_state()
    processed = set(state["processed_cve_ids"])

    cves = fetch_recent_cves(days=1)
    new_cves = [c for c in cves if c["id"] not in processed]
    if not new_cves:
        print("No new relevant CVEs.")
        return

    current_rules_source = RULES_FILE.read_text()
    subprocess.run(["git", "-C", str(REPO_ROOT), "checkout", "master"], check=True)
    subprocess.run(["git", "-C", str(REPO_ROOT), "pull"], check=True)

    for cve in new_cves:
        processed.add(cve["id"])
        try:
            proposal = ask_gemini_for_rule(cve, current_rules_source)
            if proposal is None:
                continue
            pr_url = open_pr_for_rule(cve, proposal)
            notify(f"[yousecure-scan] Novo PR proposto pro {cve['id']}: {pr_url}\nRevisar antes de dar merge.")
            subprocess.run(["git", "-C", str(REPO_ROOT), "checkout", "master"], check=True)
        except Exception as exc:  # noqa: BLE001 - one bad CVE shouldn't stop the batch
            print(f"Failed to process {cve['id']}: {exc}", file=sys.stderr)
            subprocess.run(["git", "-C", str(REPO_ROOT), "checkout", "master"], check=True)

    state["processed_cve_ids"] = sorted(processed)[-2000:]  # cap growth
    _save_state(state)


if __name__ == "__main__":
    main()
