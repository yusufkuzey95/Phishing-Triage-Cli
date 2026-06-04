"""Parse .eml email files into structured data we can triage.

We use Python's standard-library ``email`` package rather than hand-rolled
string parsing because real-world emails fold headers, bundle multiple MIME
parts, and use various encodings — all of which this parser handles correctly.
"""

from email import policy
from email.parser import BytesParser


def load_email(path):
    """Read a .eml file from disk and parse it into an EmailMessage object.

    We open the file in binary mode ("rb") so the parser sees the raw bytes and
    can deal with whatever character encoding the email uses. ``policy.default``
    gives us the modern EmailMessage API, which also decodes encoded headers
    (e.g. ``=?UTF-8?B?...?=``) into readable text for us automatically.
    """
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def parse_bytes(data):
    """Parse an email from raw bytes (e.g. text submitted via a web form).

    Same parser and policy as load_email, just from an in-memory bytes object
    instead of a file on disk.
    """
    return BytesParser(policy=policy.default).parsebytes(data)


def get_sender(msg):
    """Return the raw From header (who the email *claims* to be from)."""
    return msg["From"]


def get_subject(msg):
    """Return the Subject header."""
    return msg["Subject"]


# The headers a SOC analyst cares about most when triaging a phishing email.
KEY_HEADERS = [
    "From",
    "Reply-To",
    "Return-Path",
    "To",
    "Subject",
    "Date",
    "Authentication-Results",
]


def get_key_headers(msg):
    """Collect the triage-relevant headers into a dict.

    Most headers appear once, so ``msg[name]`` returns a single value (or None
    if the header is absent). ``Received`` is special: a mail server adds a new
    Received header at each hop, so the message can have several. We use
    ``get_all`` to capture every one as a list, since the chain of hops is what
    lets us trace where the email really came from.
    """
    headers = {name: msg[name] for name in KEY_HEADERS}
    headers["Received"] = msg.get_all("Received", [])
    return headers


def get_bodies(msg):
    """Return a list of (content_type, text) for every text body part.

    A phishing email is often ``multipart`` — the same message bundled as both a
    text/plain and a text/html version. We walk *every* part and collect both,
    because attackers frequently hide links in the HTML that aren't in the
    plain-text version. ``walk()`` yields each MIME part in turn;
    ``get_content()`` decodes the part's transfer-encoding and charset for us.
    Parts marked as attachments are skipped — those are files, not the body.
    """
    bodies = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        bodies.append((content_type, part.get_content()))
    return bodies
