# 🔍 SOC Automation Scripts

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![CI](https://github.com/fbabalola/SOC-Automation-Scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/fbabalola/SOC-Automation-Scripts/actions)

**Production-ready Python tools for Security Operations Centers.** Extract IOCs, analyze phishing emails, parse logs, enrich threat data — all from the command line.

Built for SOC analysts who need fast, reliable automation without heavy SOAR dependencies.

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/fbabalola/SOC-Automation-Scripts.git
cd SOC-Automation-Scripts

# Install
pip install -r requirements.txt

# Extract IOCs from a threat report
python tools/ioc_extractor.py --file report.txt --json

# Analyze a phishing email
python tools/email_analyzer.py --file suspicious.eml

# Parse Windows Event logs for failed logins
python tools/log_parser.py --file security.evtx --hunt failed_logins
```

---

## 📦 Tools Included

| Tool | Description | Use Case |
|------|-------------|----------|
| `ioc_extractor.py` | Extract IPs, domains, hashes, CVEs, crypto addresses from any text | Threat reports, pastes, logs |
| `email_analyzer.py` | Parse email headers, validate SPF/DKIM/DMARC, extract attachments | Phishing triage |
| `log_parser.py` | Hunt through Windows/Linux logs for suspicious patterns | Incident response |
| `threat_enricher.py` | Query VirusTotal, AbuseIPDB, Shodan for IOC context | Threat intel enrichment |
| `hash_lookup.py` | Check file hashes against known malware databases | Malware analysis |
| `defang.py` | Safely defang/refang IOCs for sharing | Report writing |

---

## 🔧 IOC Extractor

The most feature-rich tool in this collection. Extracts 15+ IOC types:

### Supported IOC Types

| Type | Example | Defang Support |
|------|---------|----------------|
| IPv4 | `192.168.1.1` | `192[.]168[.]1[.]1` |
| IPv6 | `2001:db8::1` | ✅ |
| Domain | `evil.com` | `evil[.]com` |
| URL | `http://bad.com/mal.exe` | `hxxp://bad[.]com/mal.exe` |
| Email | `attacker@evil.com` | `attacker[@]evil[.]com` |
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` | - |
| SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | - |
| SHA256 | `e3b0c44298fc1c149afbf4c8996fb924...` | - |
| CVE | `CVE-2024-12345` | - |
| Bitcoin | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | - |
| Ethereum | `0x742d35Cc6634C0532925a3b844Bc9e7595f...` | - |
| File Path | `C:\Windows\System32\cmd.exe` | - |
| Registry | `HKLM\SOFTWARE\Microsoft\...` | - |
| YARA Rule | Extracts embedded YARA | - |

### Usage Examples

```bash
# Basic extraction
python tools/ioc_extractor.py --file malware_report.pdf

# Extract only hashes
python tools/ioc_extractor.py --file report.txt --type hash

# Defang output for safe sharing
python tools/ioc_extractor.py --file report.txt --defang

# JSON output for SIEM ingestion
python tools/ioc_extractor.py --file report.txt --json --output iocs.json

# STIX 2.1 output for threat intel platforms
python tools/ioc_extractor.py --file report.txt --stix --output iocs.stix.json

# Pipe from stdin
cat threat_intel.txt | python tools/ioc_extractor.py --stdin

# Extract from URL
python tools/ioc_extractor.py --url "https://example.com/threat-report"

# Refang previously defanged IOCs
python tools/ioc_extractor.py --file defanged_report.txt --refang
```

### Output Formats

**Plain Text (default)**
```
=== IPv4 Addresses (3) ===
192.168.1.100
10.0.0.50
8.8.8.8

=== Domains (2) ===
evil-c2.com
malware-drop.net
```

**JSON**
```json
{
  "ipv4": ["192.168.1.100", "10.0.0.50"],
  "domains": ["evil-c2.com", "malware-drop.net"],
  "sha256": ["a1b2c3..."],
  "metadata": {
    "source": "report.txt",
    "extracted_at": "2026-04-30T10:15:00Z",
    "total_iocs": 5
  }
}
```

**STIX 2.1**
```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = '192.168.1.100']",
      "pattern_type": "stix"
    }
  ]
}
```

---

## 📧 Email Analyzer

Comprehensive email header analysis for phishing investigations.

### Features

- **Authentication Checks**: SPF, DKIM, DMARC pass/fail
- **Routing Analysis**: Trace email path through all servers
- **IOC Extraction**: Pull IPs, domains, URLs from headers and body
- **Attachment Analysis**: Hash attachments, detect suspicious extensions
- **Suspicion Scoring**: Flag common phishing indicators

### Usage

```bash
# Full analysis
python tools/email_analyzer.py --file phishing.eml

# JSON output
python tools/email_analyzer.py --file phishing.eml --json

# Extract only headers
python tools/email_analyzer.py --file phishing.eml --headers-only

# Check authentication only
python tools/email_analyzer.py --file phishing.eml --auth-only

# Extract attachments to directory
python tools/email_analyzer.py --file phishing.eml --extract-attachments ./attachments/
```

### Sample Output

```
╔════════════════════════════════════════════════════════════════╗
║                    EMAIL ANALYSIS REPORT                        ║
╠════════════════════════════════════════════════════════════════╣
║ Subject: Urgent: Your Account Has Been Compromised!            ║
║ From: security@paypa1.com (SUSPICIOUS - typosquat)              ║
║ Reply-To: attacker@evil.com (MISMATCH)                          ║
║ Date: 2026-04-30 08:15:00 UTC                                   ║
╠════════════════════════════════════════════════════════════════╣
║ AUTHENTICATION RESULTS                                          ║
╠════════════════════════════════════════════════════════════════╣
║ SPF:   ❌ FAIL (softfail)                                       ║
║ DKIM:  ❌ FAIL (signature mismatch)                             ║
║ DMARC: ❌ FAIL (reject policy)                                  ║
╠════════════════════════════════════════════════════════════════╣
║ ROUTING PATH (5 hops)                                           ║
╠════════════════════════════════════════════════════════════════╣
║ 1. mail.evil.com [185.234.72.19] - Origin                       ║
║ 2. relay.bulletproof.ru [91.235.116.44]                         ║
║ 3. mx1.target-company.com [203.0.113.50]                        ║
╠════════════════════════════════════════════════════════════════╣
║ ⚠️  SUSPICION SCORE: 85/100 (HIGH RISK)                         ║
║ - Domain mismatch between From and envelope                     ║
║ - Reply-To different from From                                  ║
║ - All authentication failed                                     ║
║ - Contains urgency language                                     ║
║ - Link to non-matching domain                                   ║
╚════════════════════════════════════════════════════════════════╝
```

---

## 📊 Log Parser

Hunt through logs for security-relevant events.

### Supported Log Types

| Type | Description |
|------|-------------|
| Windows Security | Failed logins, account changes, privilege use |
| Windows Sysmon | Process creation, network connections |
| Linux auth.log | SSH attempts, sudo usage |
| Apache/Nginx | Web attacks, suspicious paths |
| Firewall | Blocked connections, port scans |

### Built-in Hunts

```bash
# Failed login attempts
python tools/log_parser.py --file security.evtx --hunt failed_logins

# Lateral movement indicators
python tools/log_parser.py --file security.evtx --hunt lateral_movement

# Suspicious PowerShell
python tools/log_parser.py --file sysmon.evtx --hunt powershell_abuse

# SSH brute force
python tools/log_parser.py --file auth.log --hunt ssh_bruteforce

# Web shell activity
python tools/log_parser.py --file access.log --hunt webshell
```

---

## 🌐 Threat Enricher

Query multiple threat intel APIs for IOC context.

### Supported APIs

| Service | API Key Required | Data Returned |
|---------|-----------------|---------------|
| VirusTotal | Yes | Detection ratio, first seen, tags |
| AbuseIPDB | Yes | Abuse score, reports, ISP |
| Shodan | Yes | Open ports, services, vulns |
| OTX | Optional | Pulses, related IOCs |
| GreyNoise | Optional | Classification, actor info |

### Usage

```bash
# Set API keys (one time)
export VT_API_KEY="your-virustotal-key"
export ABUSEIPDB_KEY="your-abuseipdb-key"

# Enrich single IOC
python tools/threat_enricher.py --ioc "192.168.1.100"

# Enrich from file
python tools/threat_enricher.py --file iocs.txt --output enriched.json

# Specific service only
python tools/threat_enricher.py --ioc "evil.com" --service virustotal
```

---

## 🐳 Docker

Run without installing dependencies:

```bash
# Build
docker build -t soc-tools .

# Run IOC extractor
docker run -v $(pwd)/data:/data soc-tools ioc_extractor --file /data/report.txt

# Run email analyzer
docker run -v $(pwd)/emails:/data soc-tools email_analyzer --file /data/phish.eml
```

---

## 📁 Project Structure

```
SOC-Automation-Scripts/
├── tools/
│   ├── ioc_extractor.py      # IOC extraction
│   ├── email_analyzer.py     # Email header analysis
│   ├── log_parser.py         # Log hunting
│   ├── threat_enricher.py    # API enrichment
│   ├── hash_lookup.py        # Hash checking
│   └── defang.py             # IOC defanging
├── lib/
│   ├── patterns.py           # Regex patterns
│   ├── stix_output.py        # STIX 2.1 generator
│   └── api_clients.py        # Threat intel API clients
├── tests/
│   ├── test_ioc_extractor.py
│   ├── test_email_analyzer.py
│   └── fixtures/
├── examples/
│   ├── sample_report.txt
│   ├── sample_email.eml
│   └── sample_logs/
├── .github/
│   └── workflows/
│       └── ci.yml            # Automated testing
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=tools --cov-report=html

# Run specific test
pytest tests/test_ioc_extractor.py -v
```

---

## 🤝 Contributing

PRs welcome! Please:
1. Fork the repo
2. Create a feature branch
3. Add tests for new features
4. Run `black .` for formatting
5. Submit PR

---

## 📄 License

MIT License - use freely, attribution appreciated.

---

## 👤 Author

**Firebami Babalola**  
Security Operations Analyst | Python Automation  
[GitHub](https://github.com/fbabalola) | [LinkedIn](https://linkedin.com/in/firebami-babalola)

---

*Built for analysts who want fast, reliable tools without the overhead.*
