# Phishing Triage CLI

A command-line tool that automates the first-pass triage of a suspicious email. Point it at a
`.eml` file and it parses the message, extracts indicators of compromise (IOCs), checks those
indicators against threat-intelligence services, and produces a phishing-likelihood report with
reasoning and recommended SOC actions.

Built as a learning project to demonstrate practical SOC analyst workflows.

## What it does

1. **Parse** a `.eml` email file — sender, subject, key headers, and body.
2. **Extract IOCs** — URLs and IP addresses found in the headers and body.
3. **Enrich IOCs** — query the VirusTotal and AbuseIPDB APIs for reputation data.
4. **Report** — a triage summary: phishing-likelihood verdict, the reasoning behind it, and
   recommended analyst actions.

## Status

🚧 In active development. Progress by milestone:

- [x] M0 — Project scaffolding & hygiene
- [x] M1 — Parse a `.eml` file
- [ ] M2 — Extract IOCs (URLs + IPs)
- [ ] M3 — Enrich IOCs via VirusTotal + AbuseIPDB
- [ ] M4 — Triage report & scoring
- [ ] M5 — Polish (CLI flags, tests, docs)

## Setup

```bash
# 1. Clone the repo, then create and activate a virtual environment
py -m venv .venv
.venv\Scripts\Activate.ps1        # Windows PowerShell

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
copy .env.example .env            # then edit .env and add your keys
```

API keys are read from a local `.env` file (git-ignored). Get free keys from
[VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://www.abuseipdb.com/).

## Tech

Python 3.13 · stdlib `email` parser · `requests` · `python-dotenv` · `pytest`
