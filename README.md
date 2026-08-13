# yousecure-scan

Fast, pattern-based security scanner for your codebase. Finds hardcoded
secrets, SQL injection risk, unsafe deserialization, disabled TLS
verification, and a handful of other common issues in seconds — with an
optional second pass that sends each finding to Claude to confirm it's real
and suggest a fix, cutting false positives.

Built by [You Secure](https://yousecure.io) — we host VPS's and self-hosted
tools (n8n, WordPress, and more) for a living, and this is the same kind of
checklist we run on client servers.

## Install

```bash
pip install yousecure-scan
# or, for the AI review pass too:
pip install "yousecure-scan[ai]"
```

## Use

```bash
yousecure-scan /path/to/your/project
```

Got a live site instead of the source — a vibecoded app you didn't build
yourself, or one you don't have local access to? Scan the URL directly:

```bash
yousecure-scan --url https://example.com
```

This checks for exposed `.env`/`.git`, missing security headers (CSP, HSTS,
X-Frame-Options), wildcard CORS, and a few other things that fast,
AI-generated apps commonly ship to production with.

```bash
# with AI-confirmed findings + suggested fixes (needs ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
yousecure-scan /path/to/your/project --ai-review
```

Write the report to a file instead of stdout:

```bash
yousecure-scan . --ai-review -o security-report.md
```

## What it checks for

- Hardcoded API keys, AWS keys, and embedded private key material
- SQL queries built with string formatting/concatenation
- `eval()` / `exec()` on dynamic input
- `subprocess`/`os.system` calls with `shell=True`
- Unsafe deserialization (`pickle.loads`, `yaml.load` without `SafeLoader`)
- Weak hashes (MD5/SHA1) used for passwords/secrets
- Disabled TLS certificate verification
- Flask apps running with `debug=True`
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- Django `SECRET_KEY` left at a placeholder value
- Secrets bundled into client-side JS via `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` env vars
- Supabase `service_role` key or `firebase-admin` referenced outside a server-only context
- JWT verification allowing the `none` algorithm
- Hardcoded live Stripe secret keys
- Auth/permission checks hardcoded to always pass (`if (true) { ... isAdmin ... }`)
- Committed `.env`, SSH private keys, `.pem` files, cloud service-account JSON

`--url` (live-site mode) additionally checks for:

- Exposed `/.env`, `/.git/config`, config/credential backup files
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Wildcard CORS on the live response
- Server header disclosing software version

Rules live in [`yousecure_scan/rules.py`](yousecure_scan/rules.py) — adding
one is a single `Rule(...)` entry, no other code to touch.

## How the AI review pass works

The plain pattern scan is fast but noisy — a regex can't tell a real SQL
injection from a query built from constants. `--ai-review` sends each match
plus a few lines of surrounding context to Claude, which returns a verdict
(`real` or `false_positive`), a one-line explanation, and a suggested fix.
Only confirmed findings make it into the final report.

This step is entirely optional. Without `ANTHROPIC_API_KEY` set, the tool
still works — you just get the raw pattern matches instead of a reviewed,
lower-noise report.

## Kept current with new CVEs

A daily job ([`scripts/cve_watch.py`](scripts/cve_watch.py)) checks newly
published CVEs relevant to this scanner's coverage, asks Gemini whether any
of them justify a new detection rule, and opens a pull request with the
proposed rule if so — **always as a PR for human review, never a direct
commit to `master`**. See [`scripts/README.md`](scripts/README.md) for how
it's wired up.

## Limitations

This is a static, regex-based scanner — it doesn't parse an AST, doesn't
follow data flow, and won't catch anything that doesn't match one of the
rules above. It's meant as a fast first pass, not a replacement for a real
security audit.

## License

MIT — see [LICENSE](LICENSE).
