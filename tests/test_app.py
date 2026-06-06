"""Tests for the optional Flask web UI (app.py).

Uses Flask's built-in test client, so no real server or network is needed.
All triage runs offline (enrichment disabled) for determinism.
"""

from app import app, SAMPLE_TEXT


def _client():
    app.config.update(TESTING=True)
    return app.test_client()


def test_home_renders_form():
    html = _client().get("/").get_data(as_text=True)
    assert "PHISH//TRIAGE" in html
    assert "<textarea" in html


def test_uses_starfield_background_and_no_switcher():
    html = _client().get("/").get_data(as_text=True)
    assert "stars-far" in html        # Starfield background is baked in
    assert "bgbar" not in html        # the background switcher is gone


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
