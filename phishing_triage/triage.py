"""Combine all signals into a phishing-likelihood verdict.

Design: each detector returns a list of (weight, reason) tuples. The weights are
summed into a score, which maps to a Low/Medium/High verdict. No single signal
decides on its own — the verdict is the weight of evidence, which mirrors how a
SOC analyst actually reasons about a suspicious email.
"""

import re
from email.utils import parseaddr


def check_authentication(headers):
    """Signals from the Authentication-Results header (SPF / DKIM / DMARC).

    Failed sender authentication is one of the strongest phishing indicators: it
    means the email could not prove it really came from the domain it claims.
    """
    signals = []
    auth = headers.get("Authentication-Results")
    if not auth:
        # Absence isn't proof of anything, but it's worth noting.
        return [(1, "No Authentication-Results header present")]

    # Pull the verdict word after each mechanism, e.g. "spf=fail" -> "fail".
    results = dict(re.findall(r'(spf|dkim|dmarc)=(\w+)', auth))

    if results.get("spf") == "fail":
        signals.append((2, "SPF check failed (sending server not authorized for the domain)"))
    if results.get("dkim") in ("fail", "none"):
        signals.append((1, f"DKIM not valid (dkim={results.get('dkim')})"))
    if results.get("dmarc") == "fail":
        signals.append((3, "DMARC failed (message fails the domain owner's anti-spoofing policy)"))

    return signals


def _domain_of(header_value):
    """Extract the lowercased domain from a header like 'Name <user@dom.com>'.

    parseaddr splits the display name from the actual address, so it works for
    '"PayPal" <a@b.com>', '<a@b.com>', and 'a@b.com' alike. Returns None if there
    is no usable address.
    """
    if not header_value:
        return None
    _name, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def check_domain_alignment(headers):
    """Signal when From, Return-Path, and Reply-To domains don't match.

    Legitimate mail usually keeps these aligned. Mismatches are a classic spoofing
    tell: the visible From is faked, but bounces (Return-Path) and replies
    (Reply-To) lead to the attacker's real infrastructure.
    """
    signals = []
    from_domain = _domain_of(headers.get("From"))
    return_domain = _domain_of(headers.get("Return-Path"))
    reply_domain = _domain_of(headers.get("Reply-To"))

    if from_domain and return_domain and from_domain != return_domain:
        signals.append((2, f"From domain ({from_domain}) does not match Return-Path domain ({return_domain})"))
    if from_domain and reply_domain and from_domain != reply_domain:
        signals.append((2, f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"))

    return signals


# AbuseIPDB confidence thresholds for turning a score into a signal.
ABUSE_HIGH = 80
ABUSE_MODERATE = 25


def check_enrichment(enriched):
    """Signals from the M3 threat-intel results (AbuseIPDB IPs, VirusTotal URLs).

    Note the deliberate asymmetry: a *bad* reputation adds weight, but a *clean*
    result adds nothing — it does NOT subtract. A brand-new phishing URL is
    "clean" in VirusTotal simply because it hasn't been catalogued yet, so we
    never treat "clean" as evidence of safety.
    """
    signals = []

    for r in enriched.get("ips", []):
        score = r.get("abuse_score")
        if score is None:
            continue
        if score >= ABUSE_HIGH:
            signals.append((3, f"IP {r['ioc']} has high AbuseIPDB score ({score}, {r.get('total_reports')} reports)"))
        elif score >= ABUSE_MODERATE:
            signals.append((1, f"IP {r['ioc']} has a moderate AbuseIPDB score ({score})"))

    for r in enriched.get("urls", []):
        malicious = r.get("malicious")
        if malicious:  # not None and > 0
            signals.append((3, f"URL {r['ioc']} flagged malicious by {malicious} VirusTotal engines"))

    return signals


# Score thresholds for the final verdict.
HIGH_THRESHOLD = 6
MEDIUM_THRESHOLD = 3

ACTIONS = {
    "High": [
        "Do NOT click any links or open attachments.",
        "Quarantine/delete the email from all recipient mailboxes.",
        "Block the malicious domains and IPs at the mail gateway/firewall.",
        "Search mail logs for other recipients of the same campaign.",
        "Escalate to the incident-response process.",
    ],
    "Medium": [
        "Treat as suspicious; do not interact with links or attachments.",
        "Verify the sender through a known-good channel (not by replying).",
        "Investigate the flagged IOCs further before deciding.",
        "Consider warning the recipient.",
    ],
    "Low": [
        "No strong phishing indicators found, but this is not a guarantee.",
        "Advise the recipient to report the email if anything seems off.",
    ],
}


def _verdict_for(score):
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def assess(headers, enriched):
    """Produce the full triage assessment from headers + enrichment results.

    Returns a dict with the numeric score, the Low/Medium/High verdict, the list
    of (weight, reason) signals that drove it, and the recommended SOC actions.
    """
    signals = (
        check_authentication(headers)
        + check_domain_alignment(headers)
        + check_enrichment(enriched)
    )
    score = sum(weight for weight, _reason in signals)
    verdict = _verdict_for(score)
    return {
        "score": score,
        "verdict": verdict,
        "signals": signals,
        "recommended_actions": ACTIONS[verdict],
    }
