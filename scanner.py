"""
Network discovery: Nmap fingerprinting + optional Hyper mode
(parallel pulse sweep, then Nmap only on open ports — much faster on wide nets).
"""
from __future__ import annotations

import socket
from typing import Any

import nmap

from turbo_sweep import TOP_SIGNAL_PORTS, turbo_tcp_scan

NMAP_PROFILES: dict[str, str] = {
    "quick": "-Pn -F -T4 --open",
    "standard": "-Pn -sV -T4 --open",
    "deep": "-Pn -sV -sC --version-intensity 7 -T4 --open",
}

# Shown in UI log / tooltips (hyper is a composite pipeline, not a single Nmap string).
PROFILE_DESCRIPTION: dict[str, str] = {
    "quick": NMAP_PROFILES["quick"],
    "standard": NMAP_PROFILES["standard"],
    "deep": NMAP_PROFILES["deep"],
    "hyper": "Pulse: 128-way TCP sweep → Nmap -sV on hits only (-T5, min-rate)",
}

# Backward compatibility: full map for option menus
PROFILES: dict[str, str] = dict(PROFILE_DESCRIPTION)


def _resolve_host(target: str) -> str:
    t = target.strip()
    try:
        return socket.gethostbyname(t)
    except OSError:
        return t


def _parse_nmap_host(scanner: nmap.PortScanner, host: str) -> list[tuple]:
    results: list[tuple] = []
    if host not in scanner:
        return results
    nm_host = scanner[host]
    for proto in nm_host.all_protocols():
        ports_info = nm_host[proto]
        for port, pdata in ports_info.items():
            if isinstance(pdata, dict) and pdata.get("state") != "open":
                continue
            if not isinstance(pdata, dict):
                continue
            name = pdata.get("name") or "unknown"
            version = (pdata.get("version") or "") + (
                " " + pdata.get("extrainfo", "") if pdata.get("extrainfo") else ""
            )
            version = version.strip()
            results.append((int(port), name, version))
    return results


def _run_nmap(host: str, arguments: str) -> list[tuple]:
    scanner = nmap.PortScanner()
    try:
        scanner.scan(host, arguments=arguments)
    except nmap.PortScannerError as e:
        print("Nmap error:", e)
        return []
    out: list[tuple] = []
    for h in scanner.all_hosts():
        out.extend(_parse_nmap_host(scanner, h))
    return out


def scan_target(target: str, profile: str = "standard") -> tuple[list[tuple], str, dict[str, Any]]:
    """
    Returns (results, resolved_host, meta).

    meta may include pulse_open_ports, elapsed hints for Hyper mode.
    """
    host = _resolve_host(target)
    meta: dict[str, Any] = {"profile": profile}

    if profile == "hyper":
        pulse = turbo_tcp_scan(host, ports=TOP_SIGNAL_PORTS, timeout=0.26, max_workers=128)
        meta["pulse_open_ports"] = pulse
        if not pulse:
            meta["hyper_note"] = "Pulse found no ports in signal set; falling back to quick Nmap."
            rows = _run_nmap(host, NMAP_PROFILES["quick"])
            return rows, host, meta

        port_spec = ",".join(str(p) for p in pulse)
        args = f"-Pn -p{port_spec} -sV -T5 --open --min-rate 400 --version-intensity 6"
        rows = _run_nmap(host, args)
        meta["hyper_note"] = f"Nmap fingerprinted {len(rows)} service(s) from {len(pulse)} pulse hit(s)."
        return rows, host, meta

    args = NMAP_PROFILES.get(profile, NMAP_PROFILES["standard"])
    rows = _run_nmap(host, args)
    return rows, host, meta
