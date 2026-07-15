"""
Zero-privilege UDP Port Prober.
Sends legitimate request payloads to common UDP services and listens for responses.
Allows identifying open UDP ports without raw socket or root/admin privileges.
"""
from __future__ import annotations

import socket
from typing import Any

# Standard protocol request payloads
PROBES: dict[int, tuple[str, bytes]] = {
    53: (
        "dns",
        # DNS standard query for google.com (A record)
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    ),
    123: (
        "ntp",
        # NTP v3 client request (48 bytes)
        b"\x1b" + b"\x00" * 47
    ),
    161: (
        "snmp",
        # SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) with community "public"
        b"0&\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x000\x0e0\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    ),
    1900: (
        "ssdp",
        # SSDP discover query
        b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    )
}


def probe_udp_port(host: str, port: int, timeout: float = 1.5) -> dict[str, Any]:
    """
    Sends a UDP probe to a port and checks if any response is returned.
    Returns:
        dict: {"port": port, "service": service, "state": "open"|"unknown", "banner_preview": str}
    """
    svc_name, payload = PROBES.get(port, ("unknown", b"Ping"))
    res = {
        "port": port,
        "service": svc_name,
        "state": "unknown",
        "banner_preview": ""
    }

    try:
        # Determine socket family (IPv4 or IPv6)
        # Using getaddrinfo to support both families
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfo:
            return res
        family, socktype, proto, canonname, sockaddr = addrinfo[0]

        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, sockaddr)
            data, addr = sock.recvfrom(2048)
            if data:
                res["state"] = "open"
                # Hex or text snippet
                snippet = data[:120]
                try:
                    res["banner_preview"] = snippet.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")
                except Exception:
                    res["banner_preview"] = snippet.hex()
    except socket.timeout:
        # Typical for filtered/closed UDP ports (they silently discard)
        pass
    except OSError:
        # E.g., ICMP Port Unreachable or host unreachable
        pass
    return res


def scan_common_udp(host: str, timeout: float = 1.2) -> list[tuple[int, str, str]]:
    """
    Sweeps high-signal UDP ports.
    Returns:
        list[tuple[port, service, banner]]
    """
    results = []
    for port in PROBES.keys():
        probe_res = probe_udp_port(host, port, timeout=timeout)
        if probe_res["state"] == "open":
            results.append((
                probe_res["port"],
                probe_res["service"],
                f"UDP Open (Response: {probe_res['banner_preview'] or 'bytes'})"
            ))
    return results
