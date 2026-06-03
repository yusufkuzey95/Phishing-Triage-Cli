"""Extract Indicators of Compromise (IOCs) from parsed email text.

For phishing triage the two highest-value IOCs are URLs (the click target / payload)
and IP addresses (e.g. the sending server from the Received header). This module
finds them in the text we extracted during parsing.

Note: we use regex here to find *patterns within text*, which is what regex is good
at — unlike parsing the email's structure, where we relied on the stdlib email module.
"""

import ipaddress
import re

from phishing_triage.parser import get_bodies, get_key_headers

# Matches http:// or https:// followed by everything up to the first character
# that can't be part of a URL (whitespace, quotes, angle brackets, or a closing
# bracket/paren that usually surrounds a URL rather than belonging to it).
URL_RE = re.compile(r'https?://[^\s"\'<>)\]}]+')


def extract_urls(text):
    """Return a list of all http/https URLs found in the given text."""
    return URL_RE.findall(text)


# Loosely matches "four numbers separated by dots". This finds *candidates*; it
# does NOT guarantee a valid IP (e.g. it would match 999.999.999.999). We rely on
# the ipaddress module below to reject those.
#
# The lookarounds keep us from grabbing four octets out of the MIDDLE of a longer
# dotted number (a version string like 1.2.3.4.5):
#   (?<![\d.])  = not preceded by a digit or a dot
#   (?!\.?\d)   = not followed by (an optional dot and then) a digit
# We must NOT reject a plain trailing dot, because an IP often ends a sentence
# ("...from 203.0.113.77.") — that period is not part of the address. So the
# lookahead only rejects a dot that is followed by another digit (a 5th octet).
IPV4_CANDIDATE_RE = re.compile(r'(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)')


def extract_ips(text):
    """Return a list of valid IPv4 addresses found in the given text.

    Two-step approach: the regex finds anything *shaped* like an IPv4 address,
    then ipaddress.ip_address() validates each candidate and discards anything
    that isn't a real address. This "loose find, strict validate" pattern avoids
    false positives like 999.999.999.999 or version strings like 1.2.3.4.5.
    """
    valid = []
    for candidate in IPV4_CANDIDATE_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)  # raises ValueError if not a real IP
            valid.append(candidate)
        except ValueError:
            continue
    return valid


def defang(ioc):
    """Rewrite an IOC so it is not clickable/resolvable, for safe reporting.

    e.g. http://evil.com/x -> hxxp://evil[.]com/x   and   1.2.3.4 -> 1[.]2[.]3[.]4
    Analysts share IOCs in tickets and chat; defanging stops anyone (or an app)
    from accidentally opening a live malicious link.
    """
    return ioc.replace("http", "hxxp").replace(".", "[.]")


def _dedupe(items):
    """Return items with duplicates removed, preserving first-seen order.

    dict keys are unique and keep insertion order, so dict.fromkeys is a concise
    order-preserving de-dupe.
    """
    return list(dict.fromkeys(items))


def extract_iocs(msg):
    """Pull all IOCs from a parsed email: URLs and IPs from the body AND headers.

    Returns a dict like {"urls": [...], "ips": [...]} with duplicates removed.
    We search the body parts plus the header values, because key indicators live
    in both places (malicious URLs in the body, the sending server's IP up in the
    Received header).
    """
    texts = [text for _content_type, text in get_bodies(msg)]

    for name, value in get_key_headers(msg).items():
        if name == "Received":
            texts.extend(value)          # Received is a list (one per hop)
        elif value:
            texts.append(value)

    urls, ips = [], []
    for text in texts:
        urls.extend(extract_urls(text))
        ips.extend(extract_ips(text))

    return {"urls": _dedupe(urls), "ips": _dedupe(ips)}
