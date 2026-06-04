"""Tests for the optional Flask web UI (app.py).

Uses Flask's built-in test client, so no real server or network is needed.
All triage runs offline (enrichment disabled) for determinism.
"""

import re

from app import app, SAMPLE_TEXT


def _client():
    app.config.update(TESTING=True)
    return app.test_client()


def _active_bg(html):
    m = re.search(r'bgopt active[^>]*>([^<]+)<', html)
    return m.group(1).strip() if m else None


def test_home_renders_form():
    html = _client().get("/").get_data(as_text=True)
    assert "PHISH//TRIAGE" in html
    assert "<textarea" in html


def test_default_background_is_starfield():
    html = _client().get("/").get_data(as_text=True)
    assert "Starfield" in _active_bg(html)


def test_invalid_background_falls_back_to_default():
    html = _client().get("/?bg=99").get_data(as_text=True)
    assert "Starfield" in _active_bg(html)


def test_background_can_be_selected():
    html = _client().get("/?bg=4").get_data(as_text=True)
    assert "Digital Rain" in _active_bg(html)


def test_demo_mode_renders_sample_report():
    # ?demo=1 (offline) shows the bundled sample's verdict without any input.
    html = _client().get("/?demo=1").get_data(as_text=True)
    assert "High" in html and "THREAT" in html


def test_post_pasted_email_is_analyzed():
    # Posting the raw sample (enrich unchecked -> offline) returns a High verdict.
    resp = _client().post("/", data={"eml": SAMPLE_TEXT})
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "High" in html
