"""
Deep DNS snapshot (A, AAAA, MX, NS, TXT, SOA, CNAME) via dnspython.
Skips gracefully for bare IPs. Also queries apex domain for mail/NS records when host is a subdomain.
"""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver


def _is_ipv4(s: str) -> bool:
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _naive_apex(host: str) -> str | None:
    parts = host.strip().lower().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def _resolve_many(name: str, lifetime: float = 2.5) -> dict[str, Any]:
    out: dict[str, Any] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        try:
            ans = resolver.resolve(name, rtype, lifetime=lifetime)
            out[rtype] = [str(r) for r in ans][:40]
        except dns.resolver.NXDOMAIN:
            out[rtype] = {"result": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            out[rtype] = {"result": "NOANSWER"}
        except dns.exception.Timeout:
            out[rtype] = {"result": "TIMEOUT"}
        except Exception as e:
            out[rtype] = {"error": type(e).__name__, "msg": str(e)[:120]}
    return out


def deep_dns_snapshot(hostname: str) -> dict[str, Any]:
    """
    Returns {"host": {...}, "apex": {...}?, "apex_name": str?}
    """
    h = hostname.strip().rstrip(".")
    if not h or _is_ipv4(h):
        return {"note": "skipped_ipv4", "host": {}}

    host_records = _resolve_many(h)
    blob: dict[str, Any] = {"host": host_records}

    apex = _naive_apex(h)
    if apex and apex != h:
        blob["apex_name"] = apex
        blob["apex"] = _resolve_many(apex)

    return blob
