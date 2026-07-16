import sqlite3
from urllib.parse import quote
import requests

NVD_HEADERS = {
    "User-Agent": "AutoVulnScanner/1.0 (security research; contact: local)",
    "Accept": "application/json",
}

DB_PATH = "cve_cache.db"


def init_db() -> None:
    """Initializes a local cache database to store CVE details, allowing offline lookups."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_key TEXT PRIMARY KEY,
                cve_json TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def get_cached_cves(query_key: str) -> list[tuple[str, str]] | None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT cve_json, updated_at FROM cve_cache WHERE query_key = ?", (query_key,))
            row = cursor.fetchone()
            if row:
                cve_json, updated_at_str = row
                # Check cache age (invalidate after 7 days to poll for newly discovered CVEs)
                from datetime import datetime, timezone
                try:
                    updated_at = datetime.strptime(updated_at_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - updated_at).days
                    if age_days < 7:
                        return [tuple(x) for x in json.loads(cve_json)]
                    else:
                        # Stale cache: remove it to allow refreshing against latest NVD CVE releases
                        conn.execute("DELETE FROM cve_cache WHERE query_key = ?", (query_key,))
                        conn.commit()
                except Exception:
                    # In case of formatting anomaly, default to return cached data
                    return [tuple(x) for x in json.loads(cve_json)]
    except Exception:
        pass
    return None


def cache_cves(query_key: str, results: list[tuple[str, str]]) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (query_key, cve_json) VALUES (?, ?)",
                (query_key, json.dumps(results))
            )
            conn.commit()
    except Exception:
        pass


import json

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
    init_db()
    
    # Generate unique query key
    query_key = ""
    if cpes:
        query_key = f"cpe:{','.join(sorted(filter(None, cpes)))}"
    else:
        query_key = f"key:{service}:{version}"
        
    # Check cache first (resolves NVD API offline/timeout limitations)
    cached = get_cached_cves(query_key)
    if cached is not None:
        return cached

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
                response = requests.get(url, headers=NVD_HEADERS, timeout=8)
                response.raise_for_status()
                data = response.json()
                parsed = _parse_nvd_response(data)
                if parsed:
                    vulnerabilities.extend(parsed)
            except Exception:
                pass
            if len(vulnerabilities) >= 5:
                res = vulnerabilities[:5]
                cache_cves(query_key, res)
                return res

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
            response = requests.get(url, headers=NVD_HEADERS, timeout=8)
            response.raise_for_status()
            data = response.json()
            vulnerabilities.extend(_parse_nvd_response(data))
        except Exception:
            pass

    res = vulnerabilities[:5]
    if res:
        cache_cves(query_key, res)
    return res
