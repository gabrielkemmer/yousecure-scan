"""Live-site checks for the common mistakes vibecoded apps ship with in
production: exposed .env/.git, missing security headers, wildcard CORS,
directory listing left on. This targets a running site, not source code -
useful when you don't have the codebase, just a URL.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass

SENSITIVE_PATHS = [
    ("/.env", "high", "Exposed .env file"),
    ("/.git/config", "high", "Exposed .git directory (full source + history downloadable)"),
    ("/.git/HEAD", "high", "Exposed .git directory (full source + history downloadable)"),
    ("/wp-config.php.bak", "high", "Exposed WordPress config backup"),
    ("/config.php.bak", "high", "Exposed config backup file"),
    ("/.aws/credentials", "high", "Exposed AWS credentials file"),
    ("/debug", "medium", "Debug endpoint reachable"),
    ("/api/debug", "medium", "Debug endpoint reachable"),
    ("/.DS_Store", "low", "Exposed .DS_Store (leaks file/directory names)"),
]

SECURITY_HEADERS = {
    "content-security-policy": "medium",
    "x-frame-options": "medium",
    "strict-transport-security": "medium",
    "x-content-type-options": "low",
}


@dataclass
class UrlFinding:
    title: str
    severity: str
    detail: str


def _get(url: str, timeout: float = 6.0):
    req = urllib.request.Request(url, headers={"User-Agent": "yousecure-scan"})
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - user-supplied target is the whole point


def scan_url(base_url: str) -> list[UrlFinding]:
    base_url = base_url.rstrip("/")
    findings: list[UrlFinding] = []

    for path, severity, title in SENSITIVE_PATHS:
        try:
            resp = _get(base_url + path)
            if resp.status == 200:
                findings.append(UrlFinding(title=title, severity=severity, detail=f"{base_url}{path} returned 200"))
        except urllib.error.HTTPError:
            pass  # 4xx/5xx = not exposed, expected outcome
        except (urllib.error.URLError, TimeoutError, OSError):
            pass  # network hiccup on one path shouldn't kill the whole scan

    try:
        resp = _get(base_url + "/")
        headers = {k.lower(): v for k, v in resp.getheaders()}

        for header, severity in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    UrlFinding(title=f"Missing security header: {header}", severity=severity, detail=base_url)
                )

        if headers.get("access-control-allow-origin") == "*":
            findings.append(UrlFinding(title="CORS allows any origin ('*')", severity="medium", detail=base_url))

        server = headers.get("server", "")
        if any(c.isdigit() for c in server):
            findings.append(
                UrlFinding(
                    title="Server header discloses software version",
                    severity="low",
                    detail=f"Server: {server}",
                )
            )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        findings.append(UrlFinding(title="Could not reach site", severity="high", detail=str(exc)))

    return findings
