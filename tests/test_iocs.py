"""Tests for IOC extraction (URLs and IP addresses)."""

from pathlib import Path

from phishing_triage.parser import load_email
from phishing_triage.iocs import (
    extract_urls,
    extract_ips,
    defang,
    extract_iocs,
)

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "phishing_sample.eml"


# --- URLs ---------------------------------------------------------------

def test_extract_urls_basic():
    text = 'click http://evil.com/login or https://safe.example.com/x here'
    assert extract_urls(text) == ["http://evil.com/login", "https://safe.example.com/x"]


def test_extract_urls_stops_at_html_quote():
    # The URL must not swallow the closing quote / tag of an <a href>.
    text = '<a href="http://evil.com/path">click</a>'
    assert extract_urls(text) == ["http://evil.com/path"]


# --- IPs: the "loose find, strict validate, boundary-checked" rules -----

def test_valid_ip_is_found():
    assert extract_ips("server [185.220.101.45] ok") == ["185.220.101.45"]


def test_ip_at_end_of_sentence_is_found():
    # A trailing sentence period must NOT cause the IP to be dropped.
    assert extract_ips("contact us at 203.0.113.77.") == ["203.0.113.77"]


def test_invalid_octets_are_rejected():
    # ipaddress validation rejects octets > 255.
    assert extract_ips("fake 999.999.999.999") == []


def test_version_string_is_not_an_ip():
    # Lookarounds stop us grabbing four octets out of a longer dotted number.
    assert extract_ips("version: 1.2.3.4.5") == []


# --- defang -------------------------------------------------------------

def test_defang_url():
    assert defang("http://evil.com/x") == "hxxp://evil[.]com/x"


def test_defang_ip():
    assert defang("203.0.113.77") == "203[.]0[.]113[.]77"


# --- aggregate over a real email ----------------------------------------

def test_extract_iocs_dedupes_and_covers_body_and_headers():
    iocs = extract_iocs(load_email(SAMPLE))
    # URL appears in both body parts but should be listed once.
    assert iocs["urls"].count("http://paypa1-alerts.com/verify?id=8842") == 1
    # HTML-only URL is present.
    assert "https://secure-paypa1.account-verify-help.com/login" in iocs["urls"]
    # IP from the body AND the IP from the Received header are both captured.
    assert set(iocs["ips"]) == {"203.0.113.77", "185.220.101.45"}
