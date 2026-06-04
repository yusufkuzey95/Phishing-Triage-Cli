"""Tests for the triage scoring engine.

These use synthetic headers/enrichment dicts, so they are fast, offline, and
deterministic — no parsing or network needed to test the scoring logic.
"""

from phishing_triage.triage import (
    check_authentication,
    check_domain_alignment,
    check_enrichment,
    assess,
)


def _weight(signals):
    return sum(w for w, _ in signals)


# --- authentication ------------------------------------------------------

def test_all_auth_failures_score():
    headers = {"Authentication-Results": "mx; spf=fail; dkim=none; dmarc=fail"}
    assert _weight(check_authentication(headers)) == 6  # 2 + 1 + 3


def test_clean_auth_no_signals():
    headers = {"Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"}
    assert check_authentication(headers) == []


# --- domain alignment ----------------------------------------------------

def test_domain_mismatch_flagged():
    headers = {
        "From": '"PayPal" <security@paypa1-alerts.com>',
        "Return-Path": "<bounce@sketchy.ru>",
        "Reply-To": "recover@elsewhere.com",
    }
    assert _weight(check_domain_alignment(headers)) == 4  # two mismatches


def test_aligned_domains_no_signal():
    headers = {
        "From": "security@paypal.com",
        "Return-Path": "<bounce@paypal.com>",
        "Reply-To": "help@paypal.com",
    }
    assert check_domain_alignment(headers) == []


# --- enrichment ----------------------------------------------------------

def test_high_abuse_ip_signals():
    enriched = {"ips": [{"ioc": "1.2.3.4", "abuse_score": 100, "total_reports": 50}], "urls": []}
    assert _weight(check_enrichment(enriched)) == 3


def test_clean_reputation_adds_nothing():
    # A clean VT result must NOT reduce or add to the score.
    enriched = {
        "ips": [{"ioc": "1.2.3.4", "abuse_score": 0, "total_reports": 0}],
        "urls": [{"ioc": "http://x.com", "malicious": 0, "suspicious": 0}],
    }
    assert check_enrichment(enriched) == []


# --- overall verdict -----------------------------------------------------

def test_assess_high_verdict():
    headers = {
        "Authentication-Results": "mx; spf=fail; dkim=none; dmarc=fail",
        "From": "security@paypa1-alerts.com",
        "Return-Path": "<bounce@sketchy.ru>",
    }
    enriched = {"ips": [{"ioc": "1.2.3.4", "abuse_score": 100, "total_reports": 50}], "urls": []}
    report = assess(headers, enriched)
    assert report["verdict"] == "High"
    assert report["score"] >= 6
    assert report["recommended_actions"]  # non-empty action list


def test_assess_low_verdict_when_clean():
    headers = {
        "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        "From": "ceo@company.com",
        "Return-Path": "<ceo@company.com>",
    }
    enriched = {"ips": [], "urls": []}
    report = assess(headers, enriched)
    assert report["verdict"] == "Low"
    assert report["score"] == 0
