import requests
import json
import time
import os
from datetime import datetime, timedelta

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = "data/cve_cache.json"
CACHE_TTL_HOURS = 24

ATTACK_KEYWORDS = {
    "DDoS": ["denial of service", "DDoS", "flood attack", "SYN flood"],
    "PortScan": ["port scan", "reconnaissance", "network scan", "service enumeration"],
    "BruteForce": ["brute force", "credential stuffing", "password spray", "authentication bypass"],
}

def is_cache_fresh():
    if not os.path.exists(CACHE_FILE):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
    return datetime.now() - mtime < timedelta(hours=CACHE_TTL_HOURS)

def fetch_cves_for_keyword(keyword: str, results_per_page: int = 10) -> list[dict]:
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }
    try:
        resp = requests.get(NVD_BASE_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            english_desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0]
                or metrics.get("cvssMetricV30", [{}])[0]
                or metrics.get("cvssMetricV2", [{}])[0]
            )
            base_score = (
                cvss_data.get("cvssData", {}).get("baseScore", None)
                if cvss_data else None
            )
            published = cve.get("published", "")
            if cve_id and english_desc:
                cves.append({
                    "cve_id": cve_id,
                    "description": english_desc,
                    "base_score": base_score,
                    "published": published,
                    "keyword": keyword,
                })
        return cves
    except Exception as e:
        print(f"[WARN] Failed to fetch CVEs for '{keyword}': {e}")
        return []

def fetch_all_cves(force_refresh: bool = False) -> list[dict]:
    if not force_refresh and is_cache_fresh():
        print(f"[INFO] Loading CVEs from cache: {CACHE_FILE}")
        with open(CACHE_FILE) as f:
            return json.load(f)

    print("[INFO] Fetching CVEs from NVD API...")
    all_cves = []
    seen_ids = set()

    for attack_type, keywords in ATTACK_KEYWORDS.items():
        for keyword in keywords:
            print(f"  -> Fetching: '{keyword}'")
            cves = fetch_cves_for_keyword(keyword, results_per_page=15)
            for cve in cves:
                if cve["cve_id"] not in seen_ids:
                    cve["attack_type_hint"] = attack_type
                    all_cves.append(cve)
                    seen_ids.add(cve["cve_id"])
            time.sleep(0.7)  # NVD rate limit: ~5 req/sec without API key

    os.makedirs("data", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(all_cves, f, indent=2)

    print(f"[INFO] Fetched {len(all_cves)} unique CVEs -> saved to {CACHE_FILE}")
    return all_cves

if __name__ == "__main__":
    cves = fetch_all_cves(force_refresh=True)
    print(f"\nSample CVE:")
    print(json.dumps(cves[0], indent=2))
