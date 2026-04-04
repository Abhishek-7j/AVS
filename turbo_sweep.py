"""
Parallel TCP connect sweep — finds open ports fast before heavy fingerprinting.
Uses many short-lived connections (no root, no raw sockets).
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

# Curated high-signal ports: common services + DB + web + remote admin
TOP_SIGNAL_PORTS: tuple[int, ...] = tuple(
    sorted(
        {
            21,
            22,
            23,
            25,
            53,
            80,
            88,
            110,
            111,
            113,
            135,
            139,
            143,
            161,
            389,
            443,
            445,
            465,
            514,
            515,
            548,
            554,
            587,
            631,
            636,
            873,
            902,
            993,
            995,
            1080,
            1194,
            1433,
            1521,
            1723,
            1883,
            2049,
            2082,
            2083,
            2086,
            2087,
            2095,
            2096,
            2222,
            2375,
            2376,
            3000,
            3128,
            3268,
            3269,
            3306,
            3389,
            3478,
            4000,
            4040,
            4369,
            4443,
            4444,
            4567,
            4712,
            5000,
            5001,
            5005,
            5006,
            5007,
            5009,
            5060,
            5222,
            5223,
            5269,
            5357,
            5432,
            5601,
            5672,
            5683,
            5900,
            5984,
            5985,
            5986,
            6000,
            6379,
            6443,
            6646,
            7001,
            7077,
            8000,
            8008,
            8009,
            8080,
            8081,
            8088,
            8443,
            8888,
            9000,
            9001,
            9042,
            9090,
            9100,
            9200,
            9300,
            9443,
            10000,
            11211,
            15672,
            27017,
            27018,
            28015,
            50000,
        }
    )
)


def _probe_port(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def turbo_tcp_scan(
    host: str,
    ports: Iterable[int] | None = None,
    timeout: float = 0.28,
    max_workers: int = 128,
) -> list[int]:
    """
    Return sorted list of open TCP ports from `ports` (default: TOP_SIGNAL_PORTS).
    """
    port_list = list(ports) if ports is not None else list(TOP_SIGNAL_PORTS)
    if not port_list:
        return []

    open_ports: list[int] = []
    workers = min(max_workers, max(1, len(port_list)))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe_port, host, p, timeout): p for p in port_list}
        for fut in as_completed(futs):
            r = fut.result()
            if r is not None:
                open_ports.append(r)

    return sorted(set(open_ports))
