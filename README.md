# 🛡️ SOC Automation Scripts

**Author:** Firebami Babalola  
**Purpose:** Python automation tools for Security Operations Center analysts

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/SOC-Automation-red.svg)](https://attack.mitre.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg)](https://attack.mitre.org/)

---

## 🎯 What This Project Contains

A collection of Python scripts that automate common SOC analyst tasks:

| Script | Purpose |
|--------|---------|
| `ioc_enrichment.py` | Look up suspicious IPs, hashes, domains in VirusTotal |
| `log_parser.py` | Parse Windows Security Event Logs |
| `phishing_analyzer.py` | Analyze email headers for phishing indicators |

**Perfect for teaching students:**
- Working with security APIs (VirusTotal)
- Log analysis and parsing
- Pattern recognition for threat detection
- Real-world SOC workflows

---

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/fbabalola/SOC-Automation-Scripts.git
cd SOC-Automation-Scripts

# Install dependencies
pip install -r requirements.txt
```

### Requirements
```
requests>=2.28.0
pandas>=1.5.0
```

---

## 📦 Script 1: IOC Enrichment

Look up Indicators of Compromise (IOCs) using the VirusTotal API.

### Usage
```python
from soc_automation_scripts import IOCEnricher

# Initialize with your API key
enricher = IOCEnricher("your_virustotal_api_key")

# Check an IP address
result = enricher.check_ip("8.8.8.8")
print(result)
# {'ip': '8.8.8.8', 'country': 'US', 'malicious_count': 0, ...}

# Check a file hash
result = enricher.check_hash("44d88612fea8a8f36de82e1278abb02f")

# Check a domain
result = enricher.check_domain("example.com")
```

### What Students Learn
- REST API authentication
- JSON response parsing
- Error handling with try/except
- Working with security threat intelligence

---

## 📦 Script 2: Windows Log Parser

Parse Windows Security Event Logs for security-relevant events.

### Key Event IDs Tracked

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4624 | Successful Logon | Track who's logging in |
| 4625 | Failed Logon | Detect brute force attacks |
| 4672 | Admin Logon | Monitor privileged access |
| 4720 | User Created | Detect unauthorized accounts |
| 4726 | User Deleted | Track account changes |
| 1102 | Audit Log Cleared | 🚨 Suspicious activity! |

### Usage
```python
from soc_automation_scripts import WindowsLogParser

parser = WindowsLogParser()

# Parse log text
events = parser.parse_evtx_export(log_text)

# Find failed logons (possible brute force)
failed = parser.find_failed_logons()

# Find admin logons
admins = parser.find_admin_logons()

# Check for audit log clearing (very suspicious!)
cleared = parser.find_audit_clears()

# Get summary
summary = parser.generate_summary()
```

### What Students Learn
- Regular expressions for parsing
- Security event analysis
- Threat hunting techniques
- Windows security fundamentals

---

## 📦 Script 3: Phishing Analyzer

Analyze email headers for phishing indicators.

### Checks Performed

| Check | What It Detects |
|-------|-----------------|
| Suspicious TLD | .xyz, .top, .click domains |
| Lookalike Domain | amaz0n, g00gle, micros0ft |
| Reply-To Mismatch | Different domain than From |
| Phishing Keywords | "urgent", "suspended", "verify" |
| Urgency Tactics | ALL CAPS, multiple !!! |

### Usage
```python
from soc_automation_scripts import PhishingAnalyzer

analyzer = PhishingAnalyzer()

# Analyze email headers
headers = {
    "From": "security@amaz0n-support.xyz",
    "Reply-To": "hacker@gmail.com",
    "Subject": "URGENT: Your account suspended!"
}

indicators = analyzer.analyze_headers(headers)
verdict = analyzer.get_verdict()

print(verdict)
# {'risk_score': 85, 'verdict': 'HIGH RISK - Likely Phishing', ...}
```

### What Students Learn
- Email security concepts
- String manipulation
- Pattern matching
- Security analysis workflows

---

## 🔧 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC AUTOMATION TOOLKIT                    │
├─────────────────┬─────────────────┬─────────────────────────┤
│  IOC Enrichment │   Log Parser    │   Phishing Analyzer     │
│  (VirusTotal)   │ (Windows Events)│   (Email Headers)       │
├─────────────────┼─────────────────┼─────────────────────────┤
│  • IP lookup    │ • Event ID 4624 │ • TLD checking          │
│  • Hash lookup  │ • Event ID 4625 │ • Domain analysis       │
│  • Domain lookup│ • Event ID 4672 │ • Reply-To check        │
│  • Reputation   │ • Event ID 1102 │ • Keyword detection     │
└─────────────────┴─────────────────┴─────────────────────────┘
```

---

## 📚 Educational Value

| SOC Skill | Script | Concept |
|-----------|--------|---------|
| Threat Intelligence | IOC Enrichment | API integration, JSON parsing |
| Log Analysis | Log Parser | Regex, event correlation |
| Email Security | Phishing Analyzer | Pattern matching, risk scoring |
| Automation | All scripts | Reducing manual work |

---

## 🎓 Real-World Applications

These scripts mirror actual SOC workflows:

1. **Alert Triage** - IOC enrichment helps prioritize alerts
2. **Threat Hunting** - Log parsing identifies suspicious patterns
3. **User Reports** - Phishing analyzer processes reported emails
4. **Automation** - Reduce manual analysis time by 50%+

---

## 👨‍💻 About the Author

**Firebami Babalola** is a Security Operations Analyst with 5+ years of experience. He has worked with Splunk, Microsoft Sentinel, CrowdStrike, and built automation tools for enterprise SOC teams. Security+ and SC-200 certified.

- 🔗 [LinkedIn](https://linkedin.com/in/firebami-babalola)
- 🐙 [GitHub](https://github.com/fbabalola)

---

## 📄 License

MIT License - Use for learning, teaching, and building your own tools!
