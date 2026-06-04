"""Tests for IOC enrichment.

These tests never touch the real network. We use pytest's monkeypatch fixture to
replace requests.get with a fake, so we can test how check_ip handles each kind
of response (success, bad status, network error) deterministically and offline.
"""

import requests

from phishing_triage import enrichment
from phishing_triage.enrichment import check_ip, check_url, _vt_url_id, enrich_iocs


class FakeResponse:
    """Minimal stand-in for a requests.Response object."""

    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_check_ip_success(monkeypatch):
    payload = {"data": {"abuseConfidenceScore": 100, "totalReports": 42}}
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResponse(200, payload))

    result = check_ip("185.220.101.45", api_key="fake-key")

    assert result["found"] is True
    assert result["abuse_score"] == 100
    assert result["total_reports"] == 42
    assert result["error"] is None


def test_check_ip_no_key(monkeypatch):
    # Force "no key" regardless of the local .env.
    monkeypatch.setattr(enrichment, "get_abuseipdb_key", lambda: None)

    result = check_ip("8.8.8.8", api_key=None)

    assert result["found"] is False
    assert "no AbuseIPDB API key" in result["error"]


def test_check_ip_bad_status(monkeypatch):
    # 429 = rate limited. We should surface it as an error, not crash.
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResponse(429, {}))

    result = check_ip("1.2.3.4", api_key="fake-key")

    assert result["found"] is False
    assert result["error"] == "HTTP 429"


def test_check_ip_network_error(monkeypatch):
    def boom(*a, **kw):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "get", boom)

    result = check_ip("1.2.3.4", api_key="fake-key")

    assert result["found"] is False
    assert "request failed" in result["error"]


# --- VirusTotal URL checks ----------------------------------------------

def test_vt_url_id_has_no_padding():
    # VT's URL id is URL-safe base64 with the '=' padding stripped.
    url_id = _vt_url_id("http://evil.com/login")
    assert "=" not in url_id
    assert "/" not in url_id  # url-safe alphabet uses '_' and '-', not '/'


def test_check_url_success(monkeypatch):
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 12, "suspicious": 1, "harmless": 60,
    }}}}
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResponse(200, payload))

    result = check_url("http://evil.com/login", api_key="fake-key")

    assert result["found"] is True
    assert result["malicious"] == 12
    assert result["suspicious"] == 1
    assert result["error"] is None


def test_check_url_unknown_is_not_an_error(monkeypatch):
    # 404 = VT has never seen this URL (e.g. a zero-day phishing link).
    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResponse(404, {}))

    result = check_url("http://brand-new-phish.com", api_key="fake-key")

    assert result["found"] is False
    assert result["malicious"] == 0
    assert result["error"] is None  # NOT treated as a failure


def test_check_url_no_key(monkeypatch):
    monkeypatch.setattr(enrichment, "get_virustotal_key", lambda: None)

    result = check_url("http://evil.com", api_key=None)

    assert result["found"] is False
    assert "no VirusTotal API key" in result["error"]


# --- aggregate -----------------------------------------------------------

def test_enrich_iocs_runs_every_lookup(monkeypatch):
    # Pretend keys are configured so the lookups reach the (mocked) request.
    monkeypatch.setattr(enrichment, "get_virustotal_key", lambda: "fake-key")
    monkeypatch.setattr(enrichment, "get_abuseipdb_key", lambda: "fake-key")
    # All lookups return the same fake 200 so we can count results.
    monkeypatch.setattr(
        requests, "get",
        lambda *a, **kw: FakeResponse(200, {"data": {}}),
    )

    iocs = {"urls": ["http://a.com", "http://b.com"], "ips": ["1.2.3.4"]}
    enriched = enrich_iocs(iocs)

    assert len(enriched["urls"]) == 2
    assert len(enriched["ips"]) == 1
    assert all(r["source"] == "VirusTotal" for r in enriched["urls"])
    assert all(r["source"] == "AbuseIPDB" for r in enriched["ips"])
