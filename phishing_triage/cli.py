"""Command-line interface: tie the whole pipeline together.

    python -m phishing_triage <file.eml> [--no-enrich] [--json]

Runs parse -> extract IOCs -> enrich -> assess, then prints a triage report.
"""

import argparse
import json
import sys

from phishing_triage.parser import load_email, get_sender, get_subject, get_key_headers
from phishing_triage.iocs import extract_iocs, defang
from phishing_triage.enrichment import enrich_iocs
from phishing_triage.triage import assess


def build_report(msg, source="(email)", enrich=True):
    """Build the triage report dict from an already-parsed email message.

    Shared core used by both the CLI (file input) and the web UI (pasted text).
    """
    headers = get_key_headers(msg)
    iocs = extract_iocs(msg)
    # When enrichment is disabled we pass empty results, so reputation signals
    # simply contribute nothing — the header-based signals still apply.
    enriched = enrich_iocs(iocs) if enrich else {"urls": [], "ips": []}
    assessment = assess(headers, enriched)

    return {
        "file": source,
        "sender": get_sender(msg),
        "subject": get_subject(msg),
        "iocs": iocs,
        "enriched": enriched,
        "assessment": assessment,
    }


def run_triage(eml_path, enrich=True):
    """Run the full pipeline on one .eml file and return a report dict."""
    msg = load_email(eml_path)
    return build_report(msg, source=str(eml_path), enrich=enrich)


def format_text(report):
    """Render the report dict as a human-readable text block."""
    a = report["assessment"]
    lines = []
    bar = "=" * 64
    lines.append(bar)
    lines.append(" PHISHING TRIAGE REPORT")
    lines.append(bar)
    lines.append(f"File   : {report['file']}")
    lines.append(f"From   : {report['sender']}")
    lines.append(f"Subject: {report['subject']}")
    lines.append("")
    lines.append(f"VERDICT: {a['verdict']} phishing likelihood  (score {a['score']})")
    lines.append("")

    lines.append("Reasoning:")
    if a["signals"]:
        for weight, reason in a["signals"]:
            lines.append(f"   [+{weight}] {reason}")
    else:
        lines.append("   (no phishing indicators detected)")
    lines.append("")

    lines.append("Indicators of compromise (defanged):")
    for url in report["iocs"]["urls"]:
        lines.append(f"   URL: {defang(url)}")
    for ip in report["iocs"]["ips"]:
        lines.append(f"   IP : {defang(ip)}")
    if not report["iocs"]["urls"] and not report["iocs"]["ips"]:
        lines.append("   (none found)")
    lines.append("")

    lines.append("Recommended actions:")
    for action in a["recommended_actions"]:
        lines.append(f"   - {action}")

    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="phishing_triage",
        description="Triage a suspicious .eml email: parse it, extract IOCs, "
                    "enrich them against threat intel, and score phishing likelihood.",
    )
    parser.add_argument("eml_path", help="path to the .eml file to analyze")
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="skip the VirusTotal/AbuseIPDB API calls (fast, offline run)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output the report as JSON instead of formatted text",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        report = run_triage(args.eml_path, enrich=not args.no_enrich)
    except FileNotFoundError:
        print(f"error: file not found: {args.eml_path}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_text(report))
    return 0
