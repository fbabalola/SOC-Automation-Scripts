# SOC Automation Scripts

Hands-on SOC automation toolkit for IOC extraction, phishing triage, log parsing, and analyst workflow practice.

I built this repo to practice the kind of small automations a SOC analyst actually uses: pulling indicators from messy text, defanging IOCs before sharing, checking suspicious emails, and turning raw security data into something easier to review.

This is not a full SOAR platform or an enterprise production system. It is a practical security automation lab that shows how I think through analyst workflow problems using Python.

## What is included

| Tool | What it does | Why it matters |
|---|---|---|
| `ioc_extractor.py` | Extracts IPs, domains, URLs, hashes, emails, CVEs, and other indicators from text | Speeds up alert triage and threat report review |
| `email_analyzer.py` | Parses suspicious emails and pulls useful header/body details | Helps with phishing investigation practice |
| `log_parser.py` | Looks through Windows/Linux style logs for suspicious patterns | Supports basic hunt and incident review workflows |
| `defang.py` | Defangs/refangs indicators for safer sharing | Keeps reports readable without making malicious links clickable |
| `threat_enricher.py` | Designed for adding context from threat intel APIs | Shows how enrichment can support analyst decisions |

## Quick start

```bash
git clone https://github.com/fbabalola/SOC-Automation-Scripts.git
cd SOC-Automation-Scripts
pip install -r requirements.txt

python tools/ioc_extractor.py --file examples/sample_threat_report.txt --json
python tools/ioc_extractor.py --file examples/sample_threat_report.txt --defang
```

## Example analyst workflow

1. Start with a phishing email, SIEM note, or threat report.
2. Extract useful IOCs such as domains, IPs, URLs, hashes, emails, and CVEs.
3. Defang the output before sharing it in notes or tickets.
4. Add context from threat intelligence sources when available.
5. Save a clean summary for escalation or documentation.

## Example output

See the `examples/` folder for sample files:

- `sample_threat_report.txt`
- `sample_iocs.json`
- `sample_defanged_output.txt`

## Why this project matters

A lot of SOC work is not glamorous. It is reading alerts, cleaning up messy artifacts, checking what is real, documenting what happened, and escalating clearly. This repo is my way of practicing that muscle with Python instead of doing every step by hand.

## Skills shown

- Python scripting
- IOC extraction with regex
- JSON output formatting
- Phishing triage workflow
- Log review fundamentals
- Analyst documentation
- Security automation thinking

## Known limitations

- This is a learning/lab project, not a replacement for commercial SIEM, SOAR, or EDR tooling.
- Some detection logic is intentionally simple so the workflow is easy to follow.
- API enrichment requires valid third-party API keys where supported.
- Sample data is sanitized and should not be treated as live threat intelligence.

## Author

Firebami Babalola  
Security Operations | SC-200 | Security+ | Python Automation
