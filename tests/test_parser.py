"""Tests for the .eml parser.

Run from the project root with:  python -m pytest
"""

from pathlib import Path

from phishing_triage.parser import (
    load_email,
    parse_bytes,
    get_sender,
    get_subject,
    get_key_headers,
    get_bodies,
)

# Path to the sample email, built relative to THIS file so the test works no
# matter what directory pytest is launched from.
SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "phishing_sample.eml"


def test_sender_is_extracted():
    msg = load_email(SAMPLE)
    assert get_sender(msg) == "PayPal Security <security@paypa1-alerts.com>"


def test_parse_bytes_matches_load_email():
    # Parsing the same email from raw bytes (web form path) yields the same data.
    data = SAMPLE.read_bytes()
    msg = parse_bytes(data)
    assert get_sender(msg) == "PayPal Security <security@paypa1-alerts.com>"
    assert get_subject(msg) == "Your account has been limited - action required"


def test_subject_is_extracted():
    msg = load_email(SAMPLE)
    assert get_subject(msg) == "Your account has been limited - action required"


def test_key_headers_present():
    msg = load_email(SAMPLE)
    headers = get_key_headers(msg)
    # The spoofed sender and the mismatched return-path should both be captured.
    assert headers["From"] == "PayPal Security <security@paypa1-alerts.com>"
    assert headers["Return-Path"] == "<bounce@sketchy-mailer.ru>"


def test_both_body_parts_are_extracted():
    msg = load_email(SAMPLE)
    bodies = get_bodies(msg)
    content_types = {ctype for ctype, _text in bodies}
    # We must capture BOTH parts — the HTML hides a URL the plain text doesn't.
    assert content_types == {"text/plain", "text/html"}


def test_html_only_url_is_reachable():
    msg = load_email(SAMPLE)
    bodies = get_bodies(msg)
    html = next(text for ctype, text in bodies if ctype == "text/html")
    # This URL appears ONLY in the HTML part; proves we don't miss it.
    assert "secure-paypa1.account-verify-help.com" in html
