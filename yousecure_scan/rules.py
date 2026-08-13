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
]
