"""
Web Application Spider & Path Fuzzer for AVS.
Fuzzes common paths (e.g., /.env, /.git/HEAD) and crawls HTML links
to inspect forms for security issues (e.g., missing CSRF tokens, password over HTTP).
"""
from __future__ import annotations

import re
import requests
from urllib.parse import urljoin, urlparse
from plugins import Finding

# Common sensitive paths to fuzz
FUZZ_PATHS: dict[str, tuple[str, str, float, str, str]] = {
    "/.env": (
        "AVS-WEB-ENV", "Exposed Environment Configuration File", "Critical", 9.8,
        "Exposed .env file containing database credentials, API keys, or secret tokens.",
        "Remove the .env file from the web root or configure the web server to block access to it."
    ),
    "/.git/HEAD": (
        "AVS-WEB-GIT", "Exposed Git Repository", "High", 7.5,
        "Git repository folder is accessible, allowing recovery of source code and history.",
        "Restrict access to the /.git/ folder on the web server."
    ),
    "/config.json": (
        "AVS-WEB-CONFIG", "Exposed Configuration File", "Medium", 6.0,
        "Configuration file config.json is readable, potentially exposing sensitive API/DB connection strings.",
        "Secure the configuration file and move it out of the public document root."
    ),
    "/wp-admin/": (
        "AVS-WEB-WPADMIN", "WordPress Login Area Exposed", "Info", 0.0,
        "WordPress administrative login dashboard is exposed to the public internet.",
        "Restrict access to administrative paths using IP whitelisting or VPN.",
    ),
    "/api/swagger.json": (
        "AVS-WEB-SWAGGER", "Exposed API Documentation (Swagger/OpenAPI)", "Info", 0.0,
        "Swagger/OpenAPI specification file is accessible, exposing internal API endpoints.",
        "Restrict API schema endpoints to authenticated users only if sensitive.",
    )
}


def fuzz_sensitive_paths(base_url: str, port: int, service: str) -> list[Finding]:
    findings = []
    import config
    headers = {"User-Agent": "AutoVulnScanner-WebFuzzer/1.0"}
    headers.update(config.http_headers())

    for path, (pid, name, sev, cvss, desc, soln) in FUZZ_PATHS.items():
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            # A successful access (200 OK) indicates exposure
            if r.status_code == 200:
                body = r.text[:1000]
                # Validate heuristics to avoid false positives on default error pages
                is_valid = True
                if path == "/.env" and "DB_" not in body and "APP_" not in body:
                    is_valid = False
                if path == "/.git/HEAD" and "ref:" not in body:
                    is_valid = False
                if path == "/config.json" and "{" not in body:
                    is_valid = False

                if is_valid:
                    findings.append(
                        Finding(
                            plugin_id=pid,
                            name=name,
                            severity=sev,
                            cvss=cvss,
                            port=port,
                            service=service,
                            description=f"{desc} (Location: {url})",
                            solution=soln,
                            refs=["OWASP Top 10 — Sensitive Data Exposure"]
                        )
                    )
        except Exception:
            pass

    return findings


def crawl_and_audit_forms(base_url: str, port: int, service: str) -> list[Finding]:
    findings = []
    import config
    headers = {"User-Agent": "AutoVulnScanner-Crawler/1.0"}
    headers.update(config.http_headers())

    visited: set[str] = set()
    to_visit: list[tuple[str, int]] = [(base_url, 0)]  # (url, depth)
    max_pages = 20
    max_depth = 2
    parsed_base = urlparse(base_url)

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code != 200 or "text/html" not in r.headers.get("Content-Type", "").lower():
                continue

            html = r.text
            # Audit forms on this page
            findings.extend(_audit_html_content(html, url, port, service))

            # Extract links if not at max depth
            if depth < max_depth:
                links = re.findall(r'href=["\']([^"\']*)["\']', html, re.I)
                for link in links:
                    full_url = urljoin(url, link)
                    # Stay on the same host and protocol
                    parsed_link = urlparse(full_url)
                    if parsed_link.netloc == parsed_base.netloc and parsed_link.scheme in ("http", "https"):
                        # Strip fragments
                        clean_url = full_url.split("#")[0]
                        if clean_url not in visited:
                            to_visit.append((clean_url, depth + 1))
        except Exception:
            pass

    return findings


def _audit_html_content(html: str, page_url: str, port: int, service: str) -> list[Finding]:
    findings = []
    
    # Heuristically find form elements
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.I | re.S)
    for form_content in forms:
        # Check action parameter
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.I)
        action = action_match.group(1) if action_match else ""

        # Check if form has password input fields
        has_password = bool(re.search(r'type=["\']password["\']', form_content, re.I))

        # Check for CSRF protection token
        # Safe heuristic: look for hidden input fields with name containing 'csrf' or 'token'
        inputs = re.findall(r'<input[^>]*>', form_content, re.I)
        has_csrf = False
        for inp in inputs:
            if "hidden" in inp.lower() and ("csrf" in inp.lower() or "token" in inp.lower()):
                has_csrf = True
                break

        # Finding: Missing CSRF token in state-modifying actions
        # Heuristically assume post forms need CSRF
        is_post = "method=\"post\"" in form_content.lower() or "method='post'" in form_content.lower()
        if is_post and not has_csrf:
            findings.append(
                Finding(
                    plugin_id="AVS-WEB-CSRF-MISSING",
                    name="Missing CSRF protection token",
                    severity="Medium",
                    cvss=5.3,
                    port=port,
                    service=service,
                    description=f"HTML form (action: '{action}') on page {page_url} does not contain a CSRF token.",
                    solution="Implement Anti-CSRF tokens in all state-changing HTML forms.",
                    refs=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]
                )
            )

        # Finding: Password transmitted over HTTP
        if has_password and page_url.startswith("http://"):
            findings.append(
                Finding(
                    plugin_id="AVS-WEB-INSECURE-PASS",
                    name="Password fields transmitted over HTTP",
                    severity="High",
                    cvss=8.1,
                    port=port,
                    service=service,
                    description=f"Form containing password inputs is served/transmitted over cleartext HTTP on {page_url}.",
                    solution="Migrate web application to HTTPS and enforce TLS redirect.",
                    refs=["CWE-319"]
                )
            )

        # Finding: Autocomplete not disabled on sensitive fields
        for inp in inputs:
            if "type=\"password\"" in inp.lower() or "type='password'" in inp.lower():
                if "autocomplete=\"off\"" not in inp.lower() and "autocomplete='off'" not in inp.lower():
                    findings.append(
                        Finding(
                            plugin_id="AVS-WEB-AUTOCOMPLETE",
                            name="Sensitive form input autocomplete enabled",
                            severity="Low",
                            cvss=3.5,
                            port=port,
                            service=service,
                            description=f"Password input in form on {page_url} has autocomplete enabled.",
                            solution="Add 'autocomplete=\"off\"' to password and sensitive data input fields.",
                            refs=["OWASP Autocomplete HTML Attribute"]
                        )
                    )
                    break

    return findings
