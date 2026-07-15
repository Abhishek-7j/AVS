"""
Network discovery: Nmap fingerprinting + optional Hyper mode
(parallel pulse sweep, then Nmap only on open ports — much faster on wide nets).
"""
from __future__ import annotations

import socket
import shutil
from typing import Any

import nmap

from turbo_sweep import TOP_SIGNAL_PORTS, turbo_tcp_scan

NMAP_PROFILES: dict[str, str] = {
    "quick": "-Pn -F -T4 --open",
    "standard": "-Pn -sV -T4 --open",
    "deep": "-Pn -sV -sC --version-intensity 7 -T4 --open",
    "udp": "-Pn -sU -F -T4 --open",
}

# Shown in UI log / tooltips (hyper is a composite pipeline, not a single Nmap string).
PROFILE_DESCRIPTION: dict[str, str] = {
    "quick": NMAP_PROFILES["quick"],
    "standard": NMAP_PROFILES["standard"],
    "deep": NMAP_PROFILES["deep"],
    "udp": NMAP_PROFILES["udp"] + " (Requires Admin/Root)",
    "hyper": "Pulse: 128-way TCP sweep → Nmap -sV on hits only (-T5, min-rate)",
}

# Backward compatibility: full map for option menus
PROFILES: dict[str, str] = dict(PROFILE_DESCRIPTION)


def _resolve_host(target: str) -> tuple[str, int]:
    """
    Resolves hostname to IP. Returns (ip, version_int).
    version_int is 4 for IPv4, 6 for IPv6.
    """
    t = target.strip()
    if ":" in t:
        return t, 6
    try:
        # Try IPv4 first
        addr_info = socket.getaddrinfo(t, None, socket.AF_INET)
        if addr_info:
            return addr_info[0][4][0], 4
    except OSError:
        pass

    try:
        # Try IPv6
        addr_info = socket.getaddrinfo(t, None, socket.AF_INET6)
        if addr_info:
            return addr_info[0][4][0], 6
    except OSError:
        pass

    return t, 4


def _parse_nmap_host(scanner: nmap.PortScanner, host: str) -> tuple[list[tuple], list[int], dict[int, list[str]]]:
    results: list[tuple] = []
    filtered: list[int] = []
    cpes: dict[int, list[str]] = {}

    if not scanner.has_host(host):
        return results, filtered, cpes
    nm_host = scanner[host]
    for proto in nm_host.all_protocols():
        ports_info = nm_host[proto]
        for port, pdata in ports_info.items():
            if not isinstance(pdata, dict):
                continue
            port_num = int(port)
            state = pdata.get("state")
            if state == "filtered":
                filtered.append(port_num)
                continue
            if state != "open":
                continue
            name = pdata.get("name") or "unknown"
            version = (pdata.get("version") or "") + (
                " " + pdata.get("extrainfo", "") if pdata.get("extrainfo") else ""
            )
            version = version.strip()
            results.append((port_num, name, version))

            raw_cpe = pdata.get("cpe")
            if raw_cpe:
                if isinstance(raw_cpe, list):
                    cpes[port_num] = raw_cpe
                else:
                    cpes[port_num] = [raw_cpe]
    return results, filtered, cpes


def _run_nmap(host: str, arguments: str) -> tuple[list[tuple], list[int], dict[int, list[str]]]:
    if not shutil.which("nmap"):
        return [], [], {}
    scanner = nmap.PortScanner()
    try:
        scanner.scan(host, arguments=arguments)
    except nmap.PortScannerError as e:
        print("Nmap error:", e)
        return [], [], {}
    out: list[tuple] = []
    filtered: list[int] = []
    cpes: dict[int, list[str]] = {}
    for h in scanner.all_hosts():
        o, f, c = _parse_nmap_host(scanner, h)
        out.extend(o)
        filtered.extend(f)
        cpes.update(c)
    return out, filtered, cpes


def scan_target(target: str, profile: str = "standard") -> tuple[list[tuple], str, dict[str, Any]]:
    """
    Returns (results, resolved_host, meta).

    meta may include pulse_open_ports, elapsed hints for Hyper mode,
    filtered_ports, cpes, and scan_type.
    """
    host, ip_version = _resolve_host(target)
    meta: dict[str, Any] = {
        "profile": profile,
        "ip_version": ip_version,
        "filtered_ports": [],
        "cpes": {},
    }

    # Graceful fallback if Nmap is missing
    nmap_installed = shutil.which("nmap") is not None
    if not nmap_installed:
        meta["nmap_missing"] = True
        if profile == "udp":
            from udp_prober import scan_common_udp
            rows = scan_common_udp(host)
            return rows, host, meta
        pulse = turbo_tcp_scan(host, timeout=0.28, max_workers=128)
        rows = [(p, "open", "unknown service (Nmap missing)") for p in pulse]
        return rows, host, meta

    extra_args = " -6" if ip_version == 6 else ""

    if profile == "hyper":
        pulse = turbo_tcp_scan(host, ports=TOP_SIGNAL_PORTS, timeout=0.26, max_workers=128)
        meta["pulse_open_ports"] = pulse
        if not pulse:
            meta["hyper_note"] = "Pulse found no ports in signal set; falling back to quick Nmap."
            rows, filtered, cpes = _run_nmap(host, NMAP_PROFILES["quick"] + extra_args)
            meta["filtered_ports"] = filtered
            meta["cpes"] = cpes
            return rows, host, meta

        port_spec = ",".join(str(p) for p in pulse)
        args = f"-Pn -p{port_spec} -sV -T5 --open --min-rate 400 --version-intensity 6{extra_args}"
        rows, filtered, cpes = _run_nmap(host, args)
        meta["hyper_note"] = f"Nmap fingerprinted {len(rows)} service(s) from {len(pulse)} pulse hit(s)."
        meta["filtered_ports"] = filtered
        meta["cpes"] = cpes
        return rows, host, meta

    args = NMAP_PROFILES.get(profile, NMAP_PROFILES["standard"]) + extra_args
    rows, filtered, cpes = _run_nmap(host, args)
    
    if profile == "udp":
        from udp_prober import scan_common_udp
        python_udp = scan_common_udp(host)
        existing_ports = {r[0] for r in rows}
        for port, service, banner in python_udp:
            if port not in existing_ports:
                rows.append((port, service, banner))

    meta["filtered_ports"] = filtered
    meta["cpes"] = cpes
    return rows, host, meta
