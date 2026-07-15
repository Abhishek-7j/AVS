"""
Plugin-style vulnerability checks (Nessus/OpenVAS-style finding records).
Each finding uses a stable plugin_id for tracking and reporting.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, List, Optional
import socket
import ssl

from intel_fusion import TargetIntel, cert_days_remaining


@dataclass
class Finding:
    plugin_id: str
    name: str
    severity: str  # Info, Low, Medium, High, Critical
    cvss: float
    port: Optional[int]
    service: Optional[str]
    description: str
    solution: str
    refs: List[str]

    def to_row(self) -> tuple:
        return (self.severity, f"{self.name}: {self.description[:200]}")

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def run_tls_weakness_checks(host: str, open_ports: list[tuple]) -> list[Finding]:
    findings: list[Finding] = []
    for port, service, _ in open_ports:
        s = (service or "").lower()
        tls_like = port in (443, 8443, 4443) or s in ("https", "ssl/http")
        if not tls_like:
            continue
        ver = ""
        negotiated = ""
        try:
            with socket.create_connection((host, port), timeout=2.0) as sock:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.version() or ""
                    ver = negotiated.upper()
        except OSError:
            continue
        if ver in ("TLSV1", "TLSV1.1"):
            findings.append(
                Finding(
                    plugin_id="AVS-TLS-001",
                    name="Deprecated TLS protocol",
                    severity="High",
                    cvss=7.5,
                    port=port,
                    service=service,
                    description=f"Server negotiated {negotiated}. TLS 1.0/1.1 are deprecated and weak.",
                    solution="Disable TLS 1.0/1.1; enforce TLS 1.2+ with modern cipher suites.",
                    refs=["https://datatracker.ietf.org/doc/rfc8996/"],
                )
            )
    return findings


def run_intel_plugins(intel: TargetIntel) -> list[Finding]:
    """Headers, HSTS, CSP hints, certificate lifetime — requires gather_intel() first."""
    out: list[Finding] = []

    # DNS Subdomain Takeover Check
    dns_blob = getattr(intel, "dns_deep", {}) or {}
    for domain_key in ("host", "apex"):
        dangling = (dns_blob.get(domain_key) or {}).get("CNAME_dangling") if isinstance(dns_blob.get(domain_key), dict) else None
        if dangling:
            out.append(
                Finding(
                    plugin_id="AVS-DNS-TAKEOVER",
                    name="Potential Subdomain Takeover (Dangling CNAME)",
                    severity="High",
                    cvss=7.8,
                    port=None,
                    service="dns",
                    description=f"CNAME record points to '{dangling}', but this target does not resolve to any IP address. An attacker might be able to register the subdomain on that third-party cloud service.",
                    solution="Remove the dangling CNAME record from DNS zone files, or register/claim the resource on the third-party cloud service.",
                    refs=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"]
                )
            )
            break

    for layer in intel.http_layers:
        port = layer.get("port")
        scheme = layer.get("scheme", "")
        headers = layer.get("headers") or {}
        all_hdrs = layer.get("all_headers") or {}
        if not layer.get("reachable"):
            continue
        if layer.get("path", "/") != "/":
            continue

        if scheme == "https" and "strict-transport-security" not in headers:
            out.append(
                Finding(
                    plugin_id="AVS-WEB-HSTS",
                    name="Missing Strict-Transport-Security",
                    severity="Medium",
                    cvss=5.9,
                    port=port,
                    service="https",
                    description="HTTPS responded without an HSTS header; clients may fall back to HTTP.",
                    solution="Send Strict-Transport-Security with includeSubDomains and preload after review.",
                    refs=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                )
            )

        if "x-content-type-options" not in headers:
            out.append(
                Finding(
                    plugin_id="AVS-WEB-XCTO",
                    name="Missing X-Content-Type-Options",
                    severity="Low",
                    cvss=3.1,
                    port=port,
                    service=scheme,
                    description="No nosniff directive; older browsers may MIME-sniff responses.",
                    solution='Add header: X-Content-Type-Options: nosniff.',
                    refs=["OWASP Secure Headers"],
                )
            )

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            out.append(
                Finding(
                    plugin_id="AVS-WEB-FRAME",
                    name="Clickjacking surface (no XFO/CSP frame-ancestors)",
                    severity="Low",
                    cvss=4.3,
                    port=port,
                    service=scheme,
                    description="Neither X-Frame-Options nor CSP frame control observed on root response.",
                    solution="Use CSP frame-ancestors or X-Frame-Options DENY/SAMEORIGIN as appropriate.",
                    refs=["CWE-1021"],
                )
            )

        if scheme == "https":
            cookies = headers.get("set-cookie", "")
            if cookies and "secure" not in cookies.lower():
                out.append(
                    Finding(
                        plugin_id="AVS-WEB-COOKIE",
                        name="Set-Cookie without Secure flag",
                        severity="Medium",
                        cvss=5.4,
                        port=port,
                        service=scheme,
                        description="Session cookie may be sent over cleartext if mixed content exists.",
                        solution="Set Secure (and HttpOnly, SameSite) on sensitive cookies.",
                        refs=["CWE-614"],
                    )
                )

        xpb = headers.get("x-powered-by", "")
        if xpb:
            out.append(
                Finding(
                    plugin_id="AVS-WEB-XPB",
                    name="Technology disclosure (X-Powered-By)",
                    severity="Info",
                    cvss=2.0,
                    port=port,
                    service=scheme,
                    description=f"Header exposes stack hint: {xpb[:120]}.",
                    solution="Remove or genericize X-Powered-By in production.",
                    refs=["CWE-200"],
                )
            )

        # CORS Audit Check
        acao = all_hdrs.get("access-control-allow-origin", "")
        acac = all_hdrs.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            out.append(
                Finding(
                    plugin_id="AVS-WEB-CORS-WILDCARD",
                    name="Insecure CORS Configuration (Wildcard with Credentials)",
                    severity="High",
                    cvss=7.5,
                    port=port,
                    service=scheme,
                    description="Access-Control-Allow-Origin is configured as wildcard '*' with Allow-Credentials set to true, allowing arbitrary domain access to credentials.",
                    solution="Do not use '*' with Allow-Credentials; dynamic matching of origins should be implemented securely.",
                    refs=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"]
                )
            )

        # Cookie Security Audit Check (HttpOnly/SameSite)
        cookie_hdr = all_hdrs.get("set-cookie", "")
        if cookie_hdr:
            if "httponly" not in cookie_hdr.lower():
                out.append(
                    Finding(
                        plugin_id="AVS-WEB-COOKIE-HTTPONLY",
                        name="Set-Cookie without HttpOnly flag",
                        severity="Medium",
                        cvss=5.0,
                        port=port,
                        service=scheme,
                        description="The session cookie is missing the HttpOnly flag, allowing accessibility from JavaScript and rendering it vulnerable to theft via Cross-Site Scripting (XSS).",
                        solution="Ensure the 'HttpOnly' flag is appended to the cookie definition in response headers.",
                        refs=["OWASP Cookie Security"]
                    )
                )
            if "samesite" not in cookie_hdr.lower():
                out.append(
                    Finding(
                        plugin_id="AVS-WEB-COOKIE-SAMESITE",
                        name="Set-Cookie without SameSite flag",
                        severity="Low",
                        cvss=3.5,
                        port=port,
                        service=scheme,
                        description="The cookie is missing the SameSite flag, rendering it potentially vulnerable to CSRF.",
                        solution="Append 'SameSite=Lax' or 'SameSite=Strict' to set-cookie responses.",
                        refs=["OWASP Cookie Security"]
                    )
                )

        # HTTP Server Headers Disclosure Audit
        for hdr_key, plugin_id, name in [
            ("x-aspnet-version", "AVS-WEB-DISCLOSE-ASPNET", "ASP.NET Version Disclosure"),
            ("x-aspnetmvc-version", "AVS-WEB-DISCLOSE-ASPNETMVC", "ASP.NET MVC Version Disclosure"),
            ("server", "AVS-WEB-DISCLOSE-SERVER", "Web Server Version Disclosure")
        ]:
            val = all_hdrs.get(hdr_key, "")
            if val and (hdr_key != "server" or any(c in val for c in ("/", " ", "("))):
                out.append(
                    Finding(
                        plugin_id=plugin_id,
                        name=name,
                        severity="Low",
                        cvss=3.0,
                        port=port,
                        service=scheme,
                        description=f"Detailed software/framework signature disclosed in '{hdr_key}' header: {val[:120]}",
                        solution="Configure web server to hide specific software versions and platform framework names.",
                        refs=["CWE-200"]
                    )
                )

        # Insecure HTTP methods audit
        allow_methods = all_hdrs.get("allow", "")
        if allow_methods:
            unsafe = [m.strip().upper() for m in allow_methods.split(",") if m.strip().upper() in ("TRACE", "PUT", "DELETE")]
            if unsafe:
                out.append(
                    Finding(
                        plugin_id="AVS-WEB-HTTP-METHODS",
                        name="Unsafe HTTP Methods Enabled",
                        severity="Medium",
                        cvss=5.0,
                        port=port,
                        service=scheme,
                        description=f"Web server advertises support for unsafe HTTP methods: {', '.join(unsafe)}",
                        solution="Restrict HTTP methods allowed by the server to GET, POST, HEAD, and safe OPTIONS, blocking TRACE, PUT, and DELETE.",
                        refs=["OWASP Testing for HTTP Methods"]
                    )
                )

    for layer in intel.http_layers:
        if layer.get("path") != "/robots.txt" or not layer.get("reachable"):
            continue
        prev = (layer.get("body_preview") or "").lower()
        if "disallow:" in prev or "user-agent:" in prev:
            out.append(
                Finding(
                    plugin_id="AVS-WEB-ROBOTS",
                    name="robots.txt exposes crawl rules",
                    severity="Info",
                    cvss=2.0,
                    port=layer.get("port"),
                    service=layer.get("scheme", "http"),
                    description="robots.txt returned rules that may reveal sensitive paths (informational).",
                    solution="Ensure robots.txt does not list private admin paths; use auth instead of obscurity.",
                    refs=["CWE-200"],
                )
            )

    for tls in intel.tls_layers:
        port = tls.get("port")
        days = cert_days_remaining(tls.get("not_after") or "")
        if days is not None and days < 0:
            out.append(
                Finding(
                    plugin_id="AVS-TLS-EXP",
                    name="TLS certificate expired",
                    severity="High",
                    cvss=7.5,
                    port=port,
                    service="tls",
                    description="Certificate notAfter is in the past.",
                    solution="Renew and deploy a valid certificate chain.",
                    refs=["CWE-295"],
                )
            )
        elif days is not None and days < 21:
            out.append(
                Finding(
                    plugin_id="AVS-TLS-EXP-SOON",
                    name="TLS certificate expiring soon",
                    severity="Medium",
                    cvss=5.0,
                    port=port,
                    service="tls",
                    description=f"Certificate expires in ~{days} day(s).",
                    solution="Renew before expiry; automate ACME or enterprise PKI rotation.",
                    refs=[],
                )
            )

        subj = (tls.get("subject") or "").strip()
        iss = (tls.get("issuer") or "").strip()
        if subj and iss and subj == iss:
            out.append(
                Finding(
                    plugin_id="AVS-TLS-SELF",
                    name="Self-signed or same-subject certificate",
                    severity="Medium",
                    cvss=6.5,
                    port=port,
                    service="tls",
                    description="Issuer matches subject — often self-signed; users cannot trust without pinning.",
                    solution="Use a public or internal CA trusted by clients.",
                    refs=["CWE-295"],
                )
            )

    # Deserialize web findings and append them
    for wf in getattr(intel, "web_findings", []):
        out.append(
            Finding(
                plugin_id=wf.get("plugin_id", ""),
                name=wf.get("name", ""),
                severity=wf.get("severity", "Info"),
                cvss=wf.get("cvss", 0.0),
                port=wf.get("port"),
                service=wf.get("service"),
                description=wf.get("description", ""),
                solution=wf.get("solution", ""),
                refs=wf.get("refs", [])
            )
        )

    return _dedupe_findings(out)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.plugin_id, f.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def run_service_plugins(
    host: str,
    results: list[tuple],
) -> list[Finding]:
    """
    results: list of (port, service_name, version_string)
    """
    findings: list[Finding] = []
    risky_ports = {
        21: ("AVS-NET-001", "FTP", "Medium", 5.3, "FTP exposes credentials in cleartext if not FTPS."),
        23: ("AVS-NET-002", "Telnet", "Critical", 9.8, "Telnet sends traffic in cleartext."),
        135: ("AVS-WIN-001", "MSRPC", "Medium", 6.5, "Windows RPC endpoint exposed; review firewall scope."),
        139: ("AVS-WIN-002", "NetBIOS", "Medium", 5.0, "NetBIOS/SMB legacy surface; restrict to trusted networks."),
        445: ("AVS-WIN-003", "SMB", "High", 8.1, "SMB exposed; ensure patched (EternalBlue-era risks) and not internet-facing."),
        1433: ("AVS-DB-001", "MSSQL", "High", 7.5, "Database port exposed to network."),
        3306: ("AVS-DB-002", "MySQL", "High", 7.5, "MySQL port exposed; restrict by IP and use TLS."),
        5432: ("AVS-DB-003", "PostgreSQL", "High", 7.5, "PostgreSQL exposed; use pg_hba and VPN."),
        6379: ("AVS-DB-004", "Redis", "Critical", 9.1, "Redis often unauthenticated; never expose publicly."),
        27017: ("AVS-DB-005", "MongoDB", "High", 8.8, "MongoDB default install may lack auth; firewall."),
        9200: ("AVS-DB-006", "Elasticsearch", "High", 7.5, "Elasticsearch HTTP API; verify auth and network isolation."),
    }

    for port, service, version in results:
        s = (service or "").lower()
        v = (version or "").strip()

        if port in risky_ports:
            pid, title, sev, cvss, desc = risky_ports[port]
            if port == 23 or s == "telnet":
                findings.append(
                    Finding(
                        plugin_id=pid,
                        name=f"{title} service",
                        severity=sev,
                        cvss=cvss,
                        port=port,
                        service=service,
                        description=desc,
                        solution="Disable the service or restrict with firewall/VPN; prefer SSH over Telnet.",
                        refs=["CWE-319"],
                    )
                )
            elif port == 21 or "ftp" in s:
                findings.append(
                    Finding(
                        plugin_id=pid,
                        name=f"{title} detected",
                        severity=sev,
                        cvss=cvss,
                        port=port,
                        service=service,
                        description=desc + " Verify anonymous login and banner hardening.",
                        solution="Use SFTP/FTPS, disable anonymous FTP, enforce strong auth.",
                        refs=["CWE-319"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        plugin_id=pid,
                        name=f"{title} exposure",
                        severity=sev,
                        cvss=cvss,
                        port=port,
                        service=service,
                        description=desc,
                        solution="Bind to localhost or private networks; require VPN; enable authentication and TLS.",
                        refs=["CWE-200"],
                    )
                )

        if s == "http" and port not in (80, 8080, 8000, 8888):
            findings.append(
                Finding(
                    plugin_id="AVS-WEB-001",
                    name="HTTP on non-standard port",
                    severity="Low",
                    cvss=3.1,
                    port=port,
                    service=service,
                    description="HTTP service on unusual port may indicate dev or shadow IT.",
                    solution="Document services; move production to standard hardened configs.",
                    refs=[],
                )
            )

        if v and s not in ("", "unknown"):
            findings.append(
                Finding(
                    plugin_id="AVS-VER-001",
                    name="Version disclosure",
                    severity="Low",
                    cvss=3.7,
                    port=port,
                    service=service,
                    description=f"Banner or probe reveals version: {service} {v}.",
                    solution="Reduce banner detail; patch aggressively; monitor CVEs for this stack.",
                    refs=["CWE-200"],
                )
            )

    findings.extend(run_tls_weakness_checks(host, results))
    return _dedupe_findings(findings)


def merge_finding_lists(*groups: list[Finding]) -> list[Finding]:
    combined: list[Finding] = []
    for g in groups:
        combined.extend(g)
    return _dedupe_findings(combined)


def findings_to_legacy_tuples(findings: list[Finding]) -> list[tuple]:
    return [f.to_row() for f in findings]
