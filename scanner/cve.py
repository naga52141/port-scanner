"""
CVE lookup for software versions found in service banners.

Banner "SSH-2.0-OpenSSH_8.2p1"  ->  product openbsd:openssh, version 8.2
                                ->  NVD query cpe:2.3:a:openbsd:openssh:8.2
                                ->  known CVEs, sorted by CVSS score

Data source: NIST National Vulnerability Database (NVD) API 2.0.
Without an API key NVD allows ~5 requests per 30 seconds, so we wait between
requests and cache answers in .cve_cache.json. Set the NVD_API_KEY environment
variable (free key from nvd.nist.gov) to go faster.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          ".cve_cache.json")
CACHE_MAX_AGE = 7 * 24 * 3600  # one week

# (regex capturing the version, display name, CPE vendor:product)
PRODUCT_PATTERNS = [
    (r"OpenSSH[_ ](\d+\.\d+)", "OpenSSH", "openbsd:openssh"),
    (r"Apache/(\d+\.\d+\.\d+)", "Apache HTTP Server", "apache:http_server"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx", "f5:nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS", "microsoft:internet_information_services"),
    (r"lighttpd/(\d+\.\d+\.\d+)", "lighttpd", "lighttpd:lighttpd"),
    (r"vsFTPd (\d+\.\d+\.\d+)", "vsftpd", "vsftpd_project:vsftpd"),
    (r"ProFTPD (\d+\.\d+\.\d+[a-z]?)", "ProFTPD", "proftpd:proftpd"),
    (r"Exim (\d+\.\d+)", "Exim", "exim:exim"),
    (r"dropbear_(\d{4}\.\d+)", "Dropbear SSH", "dropbear_ssh_project:dropbear_ssh"),
    (r"PHP/(\d+\.\d+\.\d+)", "PHP", "php:php"),
    (r"Python/(\d+\.\d+\.\d+)", "Python", "python:python"),
    (r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", "OpenSSL", "openssl:openssl"),
    (r"Jetty\((\d+\.\d+\.\d+)", "Jetty", "eclipse:jetty"),
    (r"Tomcat/(\d+\.\d+\.\d+)", "Apache Tomcat", "apache:tomcat"),
]

_lock = threading.Lock()
_last_request = 0.0


def identify_software(banner):
    """Return a list of (name, version, cpe) found in a banner."""
    found = []
    for pattern, name, cpe in PRODUCT_PATTERNS:
        match = re.search(pattern, banner or "", re.IGNORECASE)
        if match:
            version = match.group(1)
            found.append((name, version, f"cpe:2.3:a:{cpe}:{version}"))
    return found


def _load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass


def _score(cve):
    """Highest available CVSS base score and severity for a CVE record."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]
            cvss = data["cvssData"]
            return cvss.get("baseScore", 0.0), cvss.get("baseSeverity") or data.get("baseSeverity", "")
    return 0.0, "UNKNOWN"


def _product_is_vulnerable(cve, cpe):
    """
    NVD also matches CVEs where our product is only the *platform*
    (e.g. a bug in a web app that runs on Python). Keep a CVE only if the
    product itself is marked vulnerable in the CVE's configurations.
    """
    vendor_product = ":".join(cpe.split(":")[3:5]) + ":"
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and f":{vendor_product}" in match.get("criteria", ""):
                    return True
    return False


def _query_nvd(cpe, timeout=30):
    global _last_request
    api_key = os.environ.get("NVD_API_KEY")
    gap = 0.7 if api_key else 6.5  # stay under NVD's public rate limit
    with _lock:
        wait = _last_request + gap - time.time()
        if wait > 0:
            time.sleep(wait)
        _last_request = time.time()

    url = NVD_URL + "?" + urllib.parse.urlencode(
        {"virtualMatchString": cpe, "resultsPerPage": 500})
    req = urllib.request.Request(url, headers={"User-Agent": "port-scanner-mini-project"})
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def lookup_cves(cpe, limit=5):
    """Return (total, top_cves) for a CPE string; uses a local cache."""
    with _lock:
        cache = _load_cache()
    entry = cache.get(cpe)
    if entry and time.time() - entry["time"] < CACHE_MAX_AGE:
        return entry["total"], entry["cves"][:limit]

    data = _query_nvd(cpe)
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        if not _product_is_vulnerable(cve, cpe):
            continue
        score, severity = _score(cve)
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        cves.append({"id": cve["id"], "score": score, "severity": severity,
                     "summary": desc[:200],
                     "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"})
    cves.sort(key=lambda c: c["score"], reverse=True)
    total = len(cves)

    with _lock:
        cache = _load_cache()
        cache[cpe] = {"time": time.time(), "total": total, "cves": cves[:20]}
        _save_cache(cache)
    return total, cves[:limit]


def enrich_with_cves(results, log=print, limit=5):
    """Add 'software', 'cves' and 'cve_total' to every result with a known banner."""
    for r in results:
        for name, version, cpe in identify_software(r.get("banner", "")):
            r.setdefault("software", []).append(f"{name} {version}")
            try:
                total, cves = lookup_cves(cpe, limit)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                log(f"[!] CVE lookup failed for {name} {version}: {e}")
                continue
            r["cve_total"] += total
            r["cves"].extend(cves)
            r["cves"].sort(key=lambda c: c["score"], reverse=True)
            log(f"[*] {name} {version} on port {r['port']}: {total} known CVE(s)")
    return results
