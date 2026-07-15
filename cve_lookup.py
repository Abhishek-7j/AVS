from urllib.parse import quote
import requests

NVD_HEADERS = {
    "User-Agent": "AutoVulnScanner/1.0 (security research; contact: local)",
    "Accept": "application/json",
}


def _parse_nvd_response(data: dict) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        descs = cve.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descs if d.get("lang") == "en"),
            descs[0].get("value", "") if descs else "",
        )
        if cve_id:
            results.append((cve_id, description[:160]))
    return results


def search_cve(service: str, version: str, cpes: list[str] | None = None) -> list[tuple[str, str]]:
    vulnerabilities: list[tuple[str, str]] = []

    # 1. Try precise CPE lookup first if available
    if cpes:
        for cpe in cpes:
            if not cpe:
                continue
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?cpeName={quote(cpe)}&resultsPerPage=5"
            )
            try:
                response = requests.get(url, headers=NVD_HEADERS, timeout=12)
                response.raise_for_status()
                data = response.json()
                parsed = _parse_nvd_response(data)
                if parsed:
                    vulnerabilities.extend(parsed)
            except Exception:
                pass
            if len(vulnerabilities) >= 5:
                return vulnerabilities[:5]

    # 2. Fall back to keyword lookup
    if not vulnerabilities:
        keyword = f"{service} {version}".strip()
        if not keyword or keyword == "unknown":
            return vulnerabilities

        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={quote(keyword)}&resultsPerPage=5"
        )
        try:
            response = requests.get(url, headers=NVD_HEADERS, timeout=12)
            response.raise_for_status()
            data = response.json()
            vulnerabilities.extend(_parse_nvd_response(data))
        except Exception:
            pass

    return vulnerabilities[:5]

