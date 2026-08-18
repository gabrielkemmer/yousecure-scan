"""Pattern-based detectors.

Each rule is deliberately narrow (one regex, one failure mode) so false
positives stay low without needing project-specific tuning. This is the
fast, free, no-API-key-required pass - see ai_review.py for the optional
second pass that sends each hit to Claude for a real verdict + fix.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    title: str
    severity: str  # "high" | "medium" | "low"
    pattern: re.Pattern
    languages: tuple[str, ...]  # file extensions this rule applies to, () = any


RULES: list[Rule] = [
    Rule(
        "secret-hardcoded-key",
        "Possible hardcoded API key / secret",
        "high",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-\/\+=]{16,}['"]"""
        ),
        (),
    ),
    Rule(
        "secret-aws-key",
        "Hardcoded AWS access key",
        "high",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        (),
    ),
    Rule(
        "secret-private-key-block",
        "Embedded private key material",
        "high",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        (),
    ),
    Rule(
        "sql-string-format",
        "SQL query built with string formatting/concatenation (injection risk)",
        "high",
        re.compile(
            r"""(?i)(execute|cursor\.execute|query)\s*\(\s*(f['"]|['"].*%s.*['"]\s*%|['"].*\{\}.*['"]\s*\.format)"""
        ),
        (".py",),
    ),
    Rule(
        "eval-exec-usage",
        "Use of eval()/exec() on dynamic input",
        "high",
        re.compile(r"\b(eval|exec)\s*\("),
        (".py",),
    ),
    Rule(
        "shell-true-subprocess",
        "subprocess/os.system call with shell=True",
        "medium",
        re.compile(r"shell\s*=\s*True"),
        (".py",),
    ),
    Rule(
        "insecure-deserialize",
        "Unsafe deserialization (pickle / yaml.load without SafeLoader)",
        "high",
        re.compile(r"\bpickle\.loads?\(|yaml\.load\((?!.*SafeLoader)"),
        (".py",),
    ),
    Rule(
        "weak-hash-for-secrets",
        "MD5/SHA1 used where a password/secret hash is implied",
        "medium",
        re.compile(r"(?i)hashlib\.(md5|sha1)\(.*(pass|pwd|secret|token)"),
        (".py",),
    ),
    Rule(
        "disabled-tls-verify",
        "TLS certificate verification disabled",
        "high",
        re.compile(r"verify\s*=\s*False"),
        (),
    ),
    Rule(
        "flask-debug-true",
        "Flask debug mode enabled (exposes interactive debugger/RCE if reachable)",
        "high",
        re.compile(r"(?i)app\.run\([^)]*debug\s*=\s*True"),
        (".py",),
    ),
    Rule(
        "cors-wildcard",
        "CORS allows any origin ('*')",
        "medium",
        re.compile(r"""(?i)Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]"""),
        (),
    ),
    Rule(
        "django-secret-key-default",
        "Django SECRET_KEY looks like a placeholder/default value",
        "medium",
        re.compile(r"(?i)SECRET_KEY\s*=\s*['\"](changeme|insecure|django-insecure|secret)"),
        (".py",),
    ),
    # -- "vibecoded" app patterns: mistakes common in fast, AI-generated
    # front-end + BaaS (Supabase/Firebase) apps that were never security
    # reviewed. These target JS/TS/JSX/TSX specifically because that's
    # where a client-bundled secret actually ships to every visitor.
    Rule(
        "client-bundled-secret-env",
        "Sensitive-looking value exposed via a client-bundled env var (NEXT_PUBLIC_/VITE_/REACT_APP_ prefix ships to the browser)",
        "high",
        re.compile(
            r"(?i)\b(NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|ADMIN|API_SECRET)[A-Z0-9_]*"
        ),
        (".js", ".jsx", ".ts", ".tsx"),
    ),
    Rule(
        "supabase-service-role-key",
        "Supabase service_role key referenced outside a server-only context (this key bypasses Row Level Security)",
        "high",
        re.compile(r"(?i)SUPABASE_SERVICE_ROLE_KEY"),
        (".js", ".jsx", ".ts", ".tsx"),
    ),
    Rule(
        "firebase-admin-in-client-code",
        "firebase-admin SDK (server-only, full-privilege) imported in what looks like client code",
        "high",
        re.compile(r"""require\(['"]firebase-admin['"]\)|from ['"]firebase-admin['"]"""),
        (".js", ".jsx", ".ts", ".tsx"),
    ),
    Rule(
        "jwt-alg-none",
        "JWT verification allows the 'none' algorithm (signature bypass)",
        "high",
        re.compile(r"""algorithms?\s*[:=]\s*\[?['"]none['"]"""),
        (".py", ".js", ".ts"),
    ),
    Rule(
        "stripe-live-key-hardcoded",
        "Live Stripe secret key hardcoded in source",
        "high",
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        (),
    ),
    Rule(
        "auth-check-disabled",
        "Auth/permission check appears hardcoded to always pass (common leftover from prompt-generated scaffolding)",
        "medium",
        re.compile(r"(?i)if\s*\(\s*(true|1)\s*\)\s*(\{|return)\s*.*?(auth|permission|isAdmin|authorized)", re.MULTILINE),
        (".js", ".jsx", ".ts", ".tsx", ".py"),
    ),    Rule(
    "path-traversal-join-without-sanitize",
    "Path traversal risk: joining request paths directly without sanitization",
    "high",
    re.compile(r"os\.path\.join\([^,]+,\s*request\.(path|url)\)"),
    (".py",),
),

]

# Filenames that shouldn't exist in a committed repo at all - checked by
# name, not content, since the risk here is the file's mere presence (a
# vibecoded app's very first `git add .` commonly sweeps these in).
SENSITIVE_FILENAMES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^\.env(\.\w+)?$"), "high", "Committed .env file (should be gitignored, never committed)"),
    (re.compile(r"^id_rsa$|^id_ed25519$"), "high", "Committed private SSH key"),
    (re.compile(r"\.pem$"), "medium", "Committed certificate/key file (.pem)"),
    (re.compile(r"^credentials\.json$|^service-account.*\.json$"), "high", "Committed cloud service-account credentials file"),
    (re.compile(r"\.sql$"), "low", "Committed raw SQL dump (check it doesn't contain real user data)"),
]
