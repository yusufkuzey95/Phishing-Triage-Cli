"""Load configuration (API keys) from the .env file.

This is where the M0 secret-handling pays off: keys live in .env (git-ignored),
never in code. python-dotenv reads that file into environment variables, and we
read them back with os.getenv. If a key is missing we return None rather than
crashing, so the rest of the tool can degrade gracefully (skip that lookup).
"""

import os

from dotenv import load_dotenv

# Read the .env file (if present) and load its KEY=value pairs into the
# environment. Called once at import time. If .env is absent, this is a no-op.
load_dotenv()


def get_virustotal_key():
    """Return the VirusTotal API key from the environment, or None if unset."""
    return os.getenv("VIRUSTOTAL_API_KEY") or None


def get_abuseipdb_key():
    """Return the AbuseIPDB API key from the environment, or None if unset."""
    return os.getenv("ABUSEIPDB_API_KEY") or None
