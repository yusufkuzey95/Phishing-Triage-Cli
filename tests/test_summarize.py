"""Tests for the optional AI summary.

No real network or API key: we pass a stand-in `client` whose messages.create()
returns a canned response (or raises), so we test our own logic deterministically.
"""

import httpx
import anthropic

from phishing_triage import summarize
from phishing_triage.summarize import generate_summary


REPORT = {
    "sender": "PayPal Security <security@paypa1-alerts.com>",
    "subject": "Your account has been limited",
    "iocs": {"urls": ["http://paypa1-alerts.com/verify"], "ips": ["185.220.101.45"]},
    "assessment": {
        "verdict": "High",
        "score": 13,
        "signals": [(3, "DMARC failed"), (3, "IP 185.220.101.45 high abuse score")],
        "recommended_actions": ["Quarantine the email."],
    },
}


class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Response:
    def __init__(self, text):
        self.content = [_Block(text)]


class FakeClient:
    """Stand-in for anthropic.Anthropic: client.messages.create(...) -> response."""

    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.messages = self  # so client.messages.create resolves to .create

    def create(self, **kwargs):
        if self._error:
            raise self._error
        return self._response


def test_summary_success():
    client = FakeClient(_Response("This is a high-risk PayPal phishing email; quarantine it."))
    summary = generate_summary(REPORT, client=client)
    assert "phishing" in summary.lower()
    assert "unavailable" not in summary


def test_summary_no_key(monkeypatch):
    # Force "no key" regardless of the local .env, and pass no client.
    monkeypatch.setattr(summarize, "get_anthropic_key", lambda: None)
    summary = generate_summary(REPORT, api_key=None)
    assert "no ANTHROPIC_API_KEY" in summary


def test_summary_api_error_is_graceful():
    err = anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com"))
    client = FakeClient(error=err)
    summary = generate_summary(REPORT, client=client)
    assert summary.startswith("(AI summary unavailable")


def test_format_report_includes_key_facts():
    text = summarize._format_report(REPORT)
    assert "Verdict: High (score 13)" in text
    assert "DMARC failed" in text
    assert "185.220.101.45" in text
