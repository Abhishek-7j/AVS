"""
Single structured view of everything collected about a target (for JSON export / APIs).
"""
from __future__ import annotations

from typing import Any


def build_target_dossier(bundle: dict[str, Any]) -> dict[str, Any]:
    intel = bundle.get("intel_fusion") or {}
    ports = bundle.get("open_ports") or []

    dns = intel.get("dns_deep") or {}
    host_rr = (dns.get("host") or {}) if isinstance(dns.get("host"), dict) else {}

    def _rr_summary(block: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for rtype, val in block.items():
            if isinstance(val, list):
                out[rtype] = {"count": len(val), "sample": val[:3]}
            elif isinstance(val, dict):
                out[rtype] = val
        return out

    return {
        "scope_note": (
            "Dossier includes network-visible data only. "
            "It does not prove completeness of vulnerabilities or misconfigurations."
        ),
        "identity": {
            "query": bundle.get("target"),
            "resolved_ipv4": bundle.get("resolved"),
            "reverse_ptr": intel.get("reverse_ptr"),
            "dns_aliases": intel.get("dns_aliases"),
        },
        "dns_summary": {
            "host_records": _rr_summary(host_rr),
            "apex_name": dns.get("apex_name"),
            "apex_records": _rr_summary(dns.get("apex") or {}) if dns.get("apex") else None,
            "tcp_quick_check": dns.get("reachability_probe"),
        },
        "surface": {
            "open_port_count": len(ports),
            "services": ports,
        },
        "application_intel": {
            "http_probes": len(intel.get("http_layers") or []),
            "tls_inspections": len(intel.get("tls_layers") or []),
        },
        "assessment": {
            "score": bundle.get("score"),
            "risk_level": bundle.get("risk_level"),
            "finding_count": len(bundle.get("findings") or []),
            "cve_hint_keys": list((bundle.get("cve_hints") or {}).keys()),
        },
    }
