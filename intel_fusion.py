"""
Surface Intel Fusion — DNS (deep + PTR), HTTP(S) full headers, TLS material, robots.txt.
Collects everything safely observable from the network for the dossier.
"""
from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from dns_deep import deep_dns_snapshot


_TITLE_RE = re.compile(rb"<title[^>]*>([^<]{1,200})</title>", re.I)
_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})")


def _is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s.strip())
        return True
    except OSError:
        return False


def sni_for_target(query: str, resolved_ip: str) -> str | None:
    q = query.strip()
    if not q or q == resolved_ip:
        return None
    if _is_ipv4(q):
        return None
    return q


@dataclass
class TargetIntel:
    query: str
    resolved_ipv4: str
    reverse_ptr: list[str] = field(default_factory=list)
    dns_aliases: list[str] = field(default_factory=list)
    dns_deep: dict[str, Any] = field(default_factory=dict)
    http_layers: list[dict[str, Any]] = field(default_factory=list)
    tls_layers: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _resolve_layers(query: str) -> tuple[str, list[str]]:
    q = query.strip()
    try:
        ipv4 = socket.gethostbyname(q)
    except OSError:
        return q, []

    aliases: list[str] = []
    try:
        _, _, alias_list = socket.gethostbyname_ex(q)
        aliases = [a for a in alias_list if a and a != q]
    except OSError:
        pass

    return ipv4, aliases


def _reverse_ptr(ip: str) -> list[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host:
            return [host]
    except OSError:
        pass
    return []


def _reachable_tcp(ip: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_fingerprint(
    host: str,
    port: int,
    use_tls: bool,
    server_hostname: str | None,
    path: str = "/",
    max_body: int = 65536,
) -> dict[str, Any]:
    scheme = "https" if use_tls else "http"
    rec: dict[str, Any] = {
        "port": port,
        "scheme": scheme,
        "path": path,
        "reachable": False,
        "status_line": "",
        "status_code": None,
        "server": "",
        "title": "",
        "headers": {},
        "all_headers": {},
        "header_count": 0,
        "body_preview": "",
        "body_bytes_seen": 0,
    }
    sock: socket.socket | None = None
    try:
        raw = socket.create_connection((host, port), timeout=2.5)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=server_hostname or host)
        else:
            sock = raw

        host_header = server_hostname or host
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: AutoVulnScanner-Intel/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)

        data = b""
        while len(data) < max_body:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data and len(data) > 16384:
                break

        if not data:
            return rec

        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if lines:
            sl = lines[0].decode(errors="replace").strip()
            rec["status_line"] = sl
            m = _STATUS_RE.match(sl)
            if m:
                rec["status_code"] = int(m.group(1))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                key = k.decode(errors="replace").strip().lower()
                val = v.decode(errors="replace").strip()
                headers[key] = val
        rec["all_headers"] = {k: (v[:500] + "…" if len(v) > 500 else v) for k, v in headers.items()}
        rec["header_count"] = len(headers)
        keep = (
            "server",
            "x-powered-by",
            "set-cookie",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "location",
        )
        rec["headers"] = {k: v for k, v in headers.items() if k in keep}
        rec["server"] = headers.get("server", "")
        if path == "/":
            m = _TITLE_RE.search(body)
            if m:
                rec["title"] = m.group(1).decode(errors="replace").strip()[:200]
        prev = body[:800].decode(errors="replace")
        rec["body_preview"] = prev[:400].replace("\r", " ").replace("\n", " ")
        rec["body_bytes_seen"] = len(body)
        rec["reachable"] = True
    except OSError:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return rec


def _tls_meta(host: str, port: int, server_hostname: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "port": port,
        "negotiated": "",
        "cipher": [],
        "subject": "",
        "issuer": "",
        "san": [],
        "not_before": "",
        "not_after": "",
        "serial_number": "",
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=2.5) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_hostname or host) as ssock:
                out["negotiated"] = ssock.version() or ""
                ciph = ssock.cipher()
                if ciph:
                    out["cipher"] = list(ciph)
                cert = ssock.getpeercert()
                if cert:
                    sub = cert.get("subject")
                    if sub:
                        parts = []
                        for rdn in sub:
                            for k, v in rdn:
                                parts.append(f"{k}={v}")
                        out["subject"] = ", ".join(parts)
                    iss = cert.get("issuer")
                    if iss:
                        iparts = []
                        for rdn in iss:
                            for k, v in rdn:
                                iparts.append(f"{k}={v}")
                        out["issuer"] = ", ".join(iparts)
                    for ext in cert.get("subjectAltName", []) or []:
                        if ext[0] == "DNS":
                            out["san"].append(ext[1])
                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    if nb:
                        out["not_before"] = nb
                    if na:
                        out["not_after"] = na
                    sn = cert.get("serialNumber")
                    if sn is not None:
                        out["serial_number"] = str(sn)
    except OSError:
        pass
    return out


def _interesting_web_ports(open_ports: list[tuple]) -> list[tuple[int, bool]]:
    want: list[tuple[int, bool]] = []
    for port, svc, _ in open_ports:
        s = (svc or "").lower()
        if port in (80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000, 9080, 8880, 8088):
            want.append((port, False))
        if port in (443, 8443, 4443, 9443, 6443) or s in ("https", "ssl/http"):
            want.append((port, True))
    seen: set[tuple[int, bool]] = set()
    out: list[tuple[int, bool]] = []
    for item in want:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def gather_intel(query: str, resolved_ip: str, scan_rows: list[tuple]) -> TargetIntel:
    ipv4, aliases = _resolve_layers(query)
    if resolved_ip:
        ipv4 = resolved_ip
    ptr = _reverse_ptr(ipv4)
    sni = sni_for_target(query, ipv4)

    dns_blob = deep_dns_snapshot(query)
    dns_blob["reachability_probe"] = {
        "tcp_80": _reachable_tcp(ipv4, 80),
        "tcp_443": _reachable_tcp(ipv4, 443),
    }

    intel = TargetIntel(
        query=query,
        resolved_ipv4=ipv4,
        reverse_ptr=ptr,
        dns_aliases=aliases,
        dns_deep=dns_blob,
    )

    jobs = _interesting_web_ports(scan_rows)
    if not jobs:
        rp = dns_blob["reachability_probe"]
        if rp["tcp_443"]:
            jobs.append((443, True))
        if rp["tcp_80"]:
            jobs.append((80, False))

    def run_http(args: tuple[int, bool, str]) -> dict[str, Any]:
        p, tls, path = args
        return _http_fingerprint(ipv4, p, tls, sni, path=path)

    http_jobs: list[tuple[int, bool, str]] = []
    for p, tls in jobs:
        http_jobs.append((p, tls, "/"))
        http_jobs.append((p, tls, "/robots.txt"))

    if http_jobs:
        with ThreadPoolExecutor(max_workers=min(24, max(1, len(http_jobs)))) as ex:
            futs = {ex.submit(run_http, j): j for j in http_jobs}
            for fut in as_completed(futs):
                rec = fut.result()
                if rec.get("reachable"):
                    intel.http_layers.append(rec)

    tls_ports = sorted({p for p, tls in jobs if tls})
    if tls_ports:
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(tls_ports)))) as ex:
            futs = [ex.submit(_tls_meta, ipv4, p, sni) for p in tls_ports]
            for fut in as_completed(futs):
                meta = fut.result()
                if meta.get("negotiated") or meta.get("subject"):
                    intel.tls_layers.append(meta)

    return intel


def cert_days_remaining(not_after: str) -> int | None:
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            return int((dt - datetime.now(timezone.utc)).total_seconds() // 86400)
        except ValueError:
            continue
    return None
