from __future__ import annotations

from intel_fusion import TargetIntel
from plugins import Finding, merge_finding_lists, run_intel_plugins, run_service_plugins

SEVERITY_WEIGHT = {
    "Info": 3,
    "Low": 8,
    "Medium": 15,
    "High": 28,
    "Critical": 45,
}


def check_vulnerabilities(
    host: str,
    results: list[tuple],
    intel: TargetIntel | None = None,
) -> list[Finding]:
    """Run network plugins + optional intel-derived checks (headers, TLS lifecycle)."""
    base = run_service_plugins(host, results)
    if intel is None:
        return base
    extra = run_intel_plugins(intel)
    return merge_finding_lists(base, extra)


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    if not findings:
        return 100, "Low"

    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 10) for f in findings)
    score = max(0, min(100, 100 - penalty))

    if any(f.severity == "Critical" for f in findings):
        score = min(score, 42)
    elif any(f.severity == "High" for f in findings):
        score = min(score, 62)
    elif any(f.severity == "Medium" for f in findings):
        score = min(score, 82)

    return score, _band_from_score(score)


def _band_from_score(score: int) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def findings_to_display_rows(findings: list[Finding]) -> list[tuple]:
    return [f.to_row() for f in findings]
