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
    ports_spec: str | None = None,
) -> dict:
    rows, resolved, meta = scan_target(target, profile=profile, ports_spec=ports_spec)
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


def print_cli_summary(bundle: dict) -> None:
    print("\n" + "=" * 75)
    print("                      AVS Assessment Summary")
    print("=" * 75)
    print(f"Target Hostname/IP : {bundle['target']}")
    print(f"Resolved Address   : {bundle['resolved']}")
    print(f"Scan Policy Profile: {bundle['profile']}")
    print(f"Assessment Time    : {bundle['scanned_at_utc'][:16].replace('T', ' ')} UTC")
    print("-" * 75)
    
    # 1. Open Ports
    print("[+] Discovered Services:")
    ports = bundle.get("open_ports", [])
    if not ports:
        print("  No open ports detected.")
    else:
        print(f"  {'PORT':<10}{'SERVICE':<15}{'VERSION'}")
        print(f"  {'-'*8:<10}{'-'*13:<15}{'-'*15}")
        for p in ports:
            print(f"  {p['port']:<10}{p['service']:<15}{p.get('version') or 'unknown'}")
            
    print("-" * 75)
    
    # 2. Vulnerability Findings
    print("[!] Discovered Vulnerabilities:")
    findings = bundle.get("findings", [])
    if not findings:
        print("  No vulnerabilities or misconfigurations detected. Target is secure!")
    else:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: order.get(x.get("severity", "info").lower(), 5))
        for f in sorted_findings:
            sev = f.get("severity", "INFO").upper()
            port_info = f"Port {f.get('port')}" if f.get("port") else "System"
            print(f"\n  [{sev}] {f.get('name')} ({f.get('plugin_id')}) — {port_info}")
            
            desc = f.get("description", "")
            if "\n\n[Why This Vulnerability Occurred / Organizational Impact]\n" in desc:
                parts = desc.split("\n\n[Why This Vulnerability Occurred / Organizational Impact]\n", 1)
                clean_desc = parts[0]
                root_cause = parts[1]
                print(f"    Description: {clean_desc}")
                print(f"    Root Cause : {root_cause}")
            else:
                print(f"    Description: {desc}")
                
            print(f"    Remediation: {f.get('solution')}")
            
    print("\n" + "-" * 75)
    
    # 3. Overall Risk Score
    print("[=] Overall Risk Rating:")
    print(f"  Security Score : {bundle['score']} / 100")
    print(f"  Risk Level     : {bundle['risk_level'].upper()} RISK")
    print("=" * 75 + "\n")


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

    # Print the terminal dashboard summary
    print_cli_summary(bundle)

    text = json.dumps(bundle, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        # Avoid double printing when outputting json directly to stdout
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
