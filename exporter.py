import json
import os
from datetime import datetime, timezone

from plugins import Finding
from target_dossier import build_target_dossier


def export_full_report(
    target: str,
    results: list[tuple],
    findings: list[Finding],
    score: int,
    risk_level: str,
    profile: str = "",
    intel: dict | None = None,
) -> str:
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in target)[:60]
    folder = f"scan_export_{safe}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(folder, exist_ok=True)

    bundle = {
        "target": target,
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "score": score,
        "risk_level": risk_level,
        "open_ports": [{"port": p, "service": s, "version": v} for p, s, v in results],
        "findings": [f.as_dict() for f in findings],
        "intel_fusion": intel,
        "cve_hints": {},
    }
    bundle["target_dossier"] = build_target_dossier(bundle)

    with open(os.path.join(folder, "scan_bundle.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    with open(os.path.join(folder, "scan_results.txt"), "w", encoding="utf-8") as f:
        f.write("port\tservice\tversion\n")
        for port, service, version in results:
            f.write(f"{port}\t{service}\t{version}\n")

    return folder
