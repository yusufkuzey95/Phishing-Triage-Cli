"""Tests for the command-line interface.

All tests use --no-enrich so they run fully offline (no API calls).
"""

import json
from pathlib import Path

from phishing_triage.cli import run_triage, format_text, main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "phishing_sample.eml"


def test_run_triage_offline_flags_phishing():
    report = run_triage(SAMPLE, enrich=False)
    assert report["assessment"]["verdict"] == "High"
    # Header-only signals (no enrichment) still score above the High threshold.
    assert report["assessment"]["score"] >= 6
    # IOCs are still extracted even when enrichment is skipped.
    assert "185.220.101.45" in report["iocs"]["ips"]


def test_format_text_includes_key_sections():
    text = format_text(run_triage(SAMPLE, enrich=False))
    assert "PHISHING TRIAGE REPORT" in text
    assert "VERDICT: High" in text
    assert "Recommended actions:" in text
    # IOCs must be shown defanged, never clickable.
    assert "hxxp://" in text
    assert "http://paypa1-alerts.com" not in text


def test_main_text_output(capsys):
    exit_code = main([str(SAMPLE), "--no-enrich"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "High phishing likelihood" in out


def test_main_json_output(capsys):
    exit_code = main([str(SAMPLE), "--no-enrich", "--json"])
    out = capsys.readouterr().out
    assert exit_code == 0
    parsed = json.loads(out)  # must be valid JSON
    assert parsed["assessment"]["verdict"] == "High"


def test_main_missing_file_returns_error(capsys):
    exit_code = main(["does_not_exist.eml", "--no-enrich"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "file not found" in err
