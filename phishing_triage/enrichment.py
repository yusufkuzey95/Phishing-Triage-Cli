"""Enrich IOCs by querying threat-intelligence APIs (AbuseIPDB, VirusTotal).

Design rule: enrichment must NEVER crash the triage. Every lookup returns a
normalized result dict and captures any problem (missing key, timeout, bad
response) in an "error" field instead of raising. That way one failed lookup
doesn't take down the whole report.
"""

import base64

import requests

from phishing_triage.config import get_abuseipdb_key, get_virustotal_key

# How long to wait (seconds) for an API before giving up. Without a timeout a
# hung server would freeze the whole tool indefinitely.
REQUEST_TIMEOUT = 10

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls/{url_id}"


def _ip_result(ip, *, found=False, abuse_score=None, total_reports=None, error=None):
    """Build the normalized result dict for an IP lookup."""
    return {
        "ioc": ip,
        "type": "ip",
        "source": "AbuseIPDB",
        "found": found,
        "abuse_score": abuse_score,
        "total_reports": total_reports,
        "error": error,
    }


def check_ip(ip, api_key=None):
    """Look up an IP's reputation on AbuseIPDB.

    Returns a normalized dict. On any failure the dict's "error" field explains
    what went wrong and the reputation fields stay None — the caller can still
    use the result without special-casing exceptions.
    """
    api_key = api_key or get_abuseipdb_key()
    if not api_key:
        return _ip_result(ip, error="no AbuseIPDB API key configured")

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        # Covers timeouts, DNS failures, connection resets, etc.
        return _ip_result(ip, error=f"request failed: {exc}")

    if response.status_code != 200:
        return _ip_result(ip, error=f"HTTP {response.status_code}")

    data = response.json().get("data", {})
    return _ip_result(
        ip,
        found=True,
        abuse_score=data.get("abuseConfidenceScore"),
        total_reports=data.get("totalReports"),
    )


def _url_result(url, *, found=False, malicious=None, suspicious=None, error=None):
    """Build the normalized result dict for a URL lookup."""
    return {
        "ioc": url,
        "type": "url",
        "source": "VirusTotal",
        "found": found,
        "malicious": malicious,
        "suspicious": suspicious,
        "error": error,
    }


def _vt_url_id(url):
    """Encode a URL into VirusTotal's URL identifier.

    VT v3 identifies a URL by the URL-safe base64 of the URL, with the trailing
    '=' padding removed. So you can't query the raw URL directly — you query its
    encoded ID.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url(url, api_key=None):
    """Look up a URL's reputation on VirusTotal.

    Returns a normalized dict; same defensive contract as check_ip (never raises;
    problems are reported in the "error" field).
    """
    api_key = api_key or get_virustotal_key()
    if not api_key:
        return _url_result(url, error="no VirusTotal API key configured")

    endpoint = VIRUSTOTAL_URL.format(url_id=_vt_url_id(url))
    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return _url_result(url, error=f"request failed: {exc}")

    # 404 means VT simply has no record of this URL yet (not an error for us —
    # a brand-new phishing URL won't be in the database). Report it as "not found"
    # with zero detections rather than a failure.
    if response.status_code == 404:
        return _url_result(url, found=False, malicious=0, suspicious=0)

    if response.status_code != 200:
        return _url_result(url, error=f"HTTP {response.status_code}")

    stats = (
        response.json()
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return _url_result(
        url,
        found=True,
        malicious=stats.get("malicious"),
        suspicious=stats.get("suspicious"),
    )


def enrich_iocs(iocs):
    """Enrich a {"urls": [...], "ips": [...]} dict (from iocs.extract_iocs).

    Returns {"urls": [<url result>, ...], "ips": [<ip result>, ...]}. Because
    each check_* call captures its own errors, one failed lookup never stops the
    others — every IOC gets a result, successful or not.

    Note on rate limits: the free VirusTotal tier allows only a few requests per
    minute, so on a real email with many URLs you may see some HTTP 429 errors.
    Those surface cleanly in each result's "error" field rather than crashing.
    """
    return {
        "urls": [check_url(url) for url in iocs.get("urls", [])],
        "ips": [check_ip(ip) for ip in iocs.get("ips", [])],
    }
