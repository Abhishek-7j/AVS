#!/usr/bin/env python3
"""
Headless AVS runner — JSON to stdout or file. For servers, CI, and scripting.
Usage (from this directory):
  python cli.py -t scanme.nmap.org --profile hyper
  python cli.py -t 192.168.1.1 --no-fusion --no-cve -o report.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from cve_lookup import search_cve
from intel_fusion import gather_intel
from scanner import PROFILE_DESCRIPTION, scan_target
from target_dossier import build_target_dossier
from vuln_checker import calculate_risk_score, check_vulnerabilities


def run_assessment(
    target: str,
    profile: str,
    fusion: bool,
    with_cve: bool,
) -> dict:
    rows, resolved, meta = scan_target(target, profile=profile)
    intel = gather_intel(target, resolved, rows) if fusion else None
    findings = check_vulnerabilities(resolved, rows, intel=intel)
    score, risk = calculate_risk_score(findings)

    cve_block: dict[str, list] = {}
    if with_cve:
        cpe_map = meta.get("cpes") or {}
        for port, service, version in rows:
            key = f"{port}/{service}"
            cves = search_cve(service, version, cpes=cpe_map.get(port))
            if cves:
                cve_block[key] = [{"id": c[0], "desc": c[1]} for c in cves]

    bundle = {
        "target": target,
        "resolved": resolved,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "profile_detail": PROFILE_DESCRIPTION.get(profile, ""),
        "scan_meta": meta,
        "open_ports": [{"port": p, "service": s, "version": v} for p, s, v in rows],
        "intel_fusion": intel.as_dict() if intel else None,
        "findings": [f.as_dict() for f in findings],
        "score": score,
        "risk_level": risk,
        "cve_hints": cve_block,
    }
    bundle["target_dossier"] = build_target_dossier(bundle)
    return bundle


def main() -> int:
    p = argparse.ArgumentParser(description="AVS — AutoVuln Scanner (headless JSON)")
    p.add_argument("-t", "--target", required=True, help="Hostname or IP")
    p.add_argument(
        "--profile",
        default="hyper",
        choices=["quick", "standard", "deep", "udp", "hyper"],
        help="Scan policy (default: hyper)",
    )
    p.add_argument("--no-fusion", action="store_true", help="Skip HTTP/TLS/DNS intel")
    p.add_argument("--no-cve", action="store_true", help="Skip NVD CVE lookups (faster)")
    p.add_argument("-o", "--output", help="Write JSON to file instead of stdout")
    args = p.parse_args()

    # Startup Banner, Legal Disclaimer, and Dependency Checks
    print("=" * 70, file=sys.stderr)
    print(" AVS — AutoVuln Scanner (Headless Mode)", file=sys.stderr)
    print(" WARNING: Scanning unauthorized targets is illegal.", file=sys.stderr)
    print("          Ensure you have explicit written consent before testing.", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    import shutil
    if not shutil.which("nmap"):
        print("[WARNING] Nmap was not found on your system PATH.", file=sys.stderr)
        print("          Port discovery will run in pure-Python TCP sweep mode.", file=sys.stderr)
        print("          To enable full fingerprinting, install Nmap from:", file=sys.stderr)
        print("          https://nmap.org/download.html", file=sys.stderr)
        print("-" * 70, file=sys.stderr)

    try:
        bundle = run_assessment(
            args.target.strip(),
            args.profile,
            fusion=not args.no_fusion,
            with_cve=not args.no_cve,
        )
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"error": str(e), "type": type(e).__name__}), file=sys.stderr)
        return 1

    text = json.dumps(bundle, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
