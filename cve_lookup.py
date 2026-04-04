from urllib.parse import quote

import requests

NVD_HEADERS = {
    "User-Agent": "AutoVulnScanner/1.0 (security research; contact: local)",
    "Accept": "application/json",
}


def search_cve(service: str, version: str) -> list[tuple[str, str]]:
    vulnerabilities: list[tuple[str, str]] = []
    keyword = f"{service} {version}".strip()
    if not keyword or keyword == "unknown":
        return vulnerabilities

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={quote(keyword)}&resultsPerPage=5"
    )

    try:
        response = requests.get(url, headers=NVD_HEADERS, timeout=25)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return vulnerabilities

    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        descs = cve.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descs if d.get("lang") == "en"),
            descs[0].get("value", "") if descs else "",
        )
        if cve_id:
            vulnerabilities.append((cve_id, description[:160]))

    return vulnerabilities
