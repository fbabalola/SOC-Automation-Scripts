#!/usr/bin/env python3
"""
SOC Automation Scripts
Author: Firebami Babalola

A collection of Python scripts for Security Operations Center automation.
Perfect for teaching students real-world cybersecurity Python applications.

Scripts included:
1. ioc_enrichment.py - Look up suspicious indicators in VirusTotal
2. log_parser.py - Parse Windows Event Logs for security events
3. phishing_analyzer.py - Analyze email headers for phishing indicators
"""

# =============================================================================
# SCRIPT 1: IOC ENRICHMENT (VirusTotal Lookup)
# =============================================================================

import requests
import json
import hashlib
import re
from datetime import datetime

class IOCEnricher:
    """
    Enrich Indicators of Compromise (IOCs) using VirusTotal API.
    
    Teaches students:
    - Working with REST APIs
    - API authentication
    - JSON parsing
    - Error handling
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize with VirusTotal API key.
        Get free API key at: https://www.virustotal.com/gui/join-us
        """
        self.api_key = api_key or "YOUR_API_KEY_HERE"
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
    
    def check_ip(self, ip_address: str) -> dict:
        """
        Check an IP address against VirusTotal.
        
        Example:
            enricher = IOCEnricher("your_api_key")
            result = enricher.check_ip("8.8.8.8")
        """
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            # Extract key information
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "ip": ip_address,
                "country": attributes.get("country", "Unknown"),
                "owner": attributes.get("as_owner", "Unknown"),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "reputation": attributes.get("reputation", 0),
                "is_suspicious": stats.get("malicious", 0) > 0
            }
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "ip": ip_address}
    
    def check_hash(self, file_hash: str) -> dict:
        """
        Check a file hash (MD5, SHA1, or SHA256) against VirusTotal.
        
        Example:
            result = enricher.check_hash("44d88612fea8a8f36de82e1278abb02f")
        """
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "hash": file_hash,
                "file_name": attributes.get("meaningful_name", "Unknown"),
                "file_type": attributes.get("type_description", "Unknown"),
                "file_size": attributes.get("size", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "is_malware": stats.get("malicious", 0) > 3
            }
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "hash": file_hash}
    
    def check_domain(self, domain: str) -> dict:
        """
        Check a domain against VirusTotal.
        
        Example:
            result = enricher.check_domain("google.com")
        """
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "domain": domain,
                "registrar": attributes.get("registrar", "Unknown"),
                "creation_date": attributes.get("creation_date", "Unknown"),
                "malicious_count": stats.get("malicious", 0),
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "is_suspicious": stats.get("malicious", 0) > 0
            }
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "domain": domain}


# =============================================================================
# SCRIPT 2: WINDOWS EVENT LOG PARSER
# =============================================================================

class WindowsLogParser:
    """
    Parse Windows Security Event Logs for security-relevant events.
    
    Teaches students:
    - File I/O operations
    - Regular expressions
    - Data parsing and filtering
    - Security event analysis
    """
    
    # Important Windows Security Event IDs
    SECURITY_EVENTS = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4634: "Logoff",
        4648: "Explicit Credential Logon",
        4672: "Admin Logon (Special Privileges)",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4723: "Password Change Attempt",
        4724: "Password Reset Attempt",
        4725: "User Account Disabled",
        4726: "User Account Deleted",
        4728: "Member Added to Security Group",
        4732: "Member Added to Local Group",
        4740: "Account Locked Out",
        4756: "Member Added to Universal Group",
        4767: "Account Unlocked",
        4768: "Kerberos TGT Requested",
        4769: "Kerberos Service Ticket Requested",
        4771: "Kerberos Pre-Auth Failed",
        4776: "NTLM Authentication",
        1102: "Audit Log Cleared",
    }
    
    # Logon Types
    LOGON_TYPES = {
        2: "Interactive (local)",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive (RDP)",
        11: "CachedInteractive",
    }
    
    def __init__(self):
        self.events = []
    
    def parse_evtx_export(self, log_text: str) -> list:
        """
        Parse exported Windows Event Log text.
        
        In a real environment, you'd use python-evtx library.
        This parses text exports for teaching purposes.
        """
        events = []
        
        # Simple pattern matching for event log entries
        event_pattern = r"Event ID:\s*(\d+).*?Date:\s*([^\n]+).*?User:\s*([^\n]+)"
        
        matches = re.findall(event_pattern, log_text, re.DOTALL)
        
        for match in matches:
            event_id = int(match[0])
            events.append({
                "event_id": event_id,
                "event_name": self.SECURITY_EVENTS.get(event_id, "Unknown Event"),
                "timestamp": match[1].strip(),
                "user": match[2].strip(),
                "is_security_relevant": event_id in self.SECURITY_EVENTS
            })
        
        self.events = events
        return events
    
    def find_failed_logons(self) -> list:
        """Find all failed logon attempts (Event ID 4625)."""
        return [e for e in self.events if e["event_id"] == 4625]
    
    def find_account_changes(self) -> list:
        """Find account creation, deletion, and modification events."""
        account_events = [4720, 4722, 4725, 4726, 4724]
        return [e for e in self.events if e["event_id"] in account_events]
    
    def find_admin_logons(self) -> list:
        """Find administrative/privileged logons (Event ID 4672)."""
        return [e for e in self.events if e["event_id"] == 4672]
    
    def find_audit_clears(self) -> list:
        """Find audit log clearing events (Event ID 1102) - suspicious!"""
        return [e for e in self.events if e["event_id"] == 1102]
    
    def generate_summary(self) -> dict:
        """Generate a summary of security events."""
        return {
            "total_events": len(self.events),
            "failed_logons": len(self.find_failed_logons()),
            "admin_logons": len(self.find_admin_logons()),
            "account_changes": len(self.find_account_changes()),
            "audit_clears": len(self.find_audit_clears()),
            "suspicious_activity": len(self.find_audit_clears()) > 0
        }


# =============================================================================
# SCRIPT 3: PHISHING EMAIL ANALYZER
# =============================================================================

class PhishingAnalyzer:
    """
    Analyze email headers and content for phishing indicators.
    
    Teaches students:
    - Email header parsing
    - String manipulation
    - Pattern recognition
    - Security analysis
    """
    
    # Known suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.tk']
    
    # Phishing keywords commonly found in subject lines
    PHISHING_KEYWORDS = [
        'urgent', 'action required', 'verify', 'suspended', 'locked',
        'confirm', 'security alert', 'unusual activity', 'expire',
        'immediately', 'account', 'password', 'click here', 'wire transfer'
    ]
    
    def __init__(self):
        self.indicators = []
        self.risk_score = 0
    
    def analyze_headers(self, headers: dict) -> list:
        """
        Analyze email headers for suspicious indicators.
        
        Example headers dict:
        {
            "From": "security@amaz0n-support.xyz",
            "Reply-To": "different@email.com",
            "Subject": "URGENT: Your account has been suspended",
            "Received": "from unknown.server.com ..."
        }
        """
        self.indicators = []
        self.risk_score = 0
        
        # Check 1: From address analysis
        from_addr = headers.get("From", "")
        self._analyze_from_address(from_addr)
        
        # Check 2: Reply-To mismatch
        reply_to = headers.get("Reply-To", "")
        self._check_reply_to_mismatch(from_addr, reply_to)
        
        # Check 3: Subject line analysis
        subject = headers.get("Subject", "")
        self._analyze_subject(subject)
        
        # Check 4: Received headers (simplified)
        received = headers.get("Received", "")
        self._analyze_received(received)
        
        return self.indicators
    
    def _analyze_from_address(self, from_addr: str):
        """Analyze the From address for suspicious patterns."""
        from_lower = from_addr.lower()
        
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if tld in from_lower:
                self.indicators.append({
                    "type": "SUSPICIOUS_TLD",
                    "detail": f"From address uses suspicious TLD: {tld}",
                    "severity": "HIGH"
                })
                self.risk_score += 30
        
        # Check for lookalike domains (number substitution)
        lookalikes = ['0' in from_lower and ('amazon' in from_lower or 'google' in from_lower or 'microsoft' in from_lower)]
        if any(lookalikes):
            self.indicators.append({
                "type": "LOOKALIKE_DOMAIN",
                "detail": f"Possible lookalike domain detected: {from_addr}",
                "severity": "HIGH"
            })
            self.risk_score += 40
    
    def _check_reply_to_mismatch(self, from_addr: str, reply_to: str):
        """Check if Reply-To differs from From address."""
        if reply_to and from_addr:
            # Extract domains
            from_domain = from_addr.split('@')[-1].split('>')[0] if '@' in from_addr else ""
            reply_domain = reply_to.split('@')[-1].split('>')[0] if '@' in reply_to else ""
            
            if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
                self.indicators.append({
                    "type": "REPLY_TO_MISMATCH",
                    "detail": f"Reply-To ({reply_domain}) differs from From ({from_domain})",
                    "severity": "MEDIUM"
                })
                self.risk_score += 25
    
    def _analyze_subject(self, subject: str):
        """Analyze subject line for phishing keywords."""
        subject_lower = subject.lower()
        
        found_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in subject_lower]
        
        if found_keywords:
            self.indicators.append({
                "type": "PHISHING_KEYWORDS",
                "detail": f"Subject contains phishing keywords: {', '.join(found_keywords)}",
                "severity": "MEDIUM"
            })
            self.risk_score += 15 * len(found_keywords)
        
        # Check for excessive urgency (all caps, exclamation marks)
        if subject.isupper() or subject.count('!') > 1:
            self.indicators.append({
                "type": "URGENCY_TACTICS",
                "detail": "Subject uses urgency tactics (ALL CAPS or multiple !)",
                "severity": "LOW"
            })
            self.risk_score += 10
    
    def _analyze_received(self, received: str):
        """Analyze Received headers for suspicious origins."""
        received_lower = received.lower()
        
        # Check for mismatched origins
        if 'unknown' in received_lower or 'unverified' in received_lower:
            self.indicators.append({
                "type": "SUSPICIOUS_ORIGIN",
                "detail": "Email originated from unknown/unverified server",
                "severity": "MEDIUM"
            })
            self.risk_score += 20
    
    def get_verdict(self) -> dict:
        """Get final analysis verdict."""
        if self.risk_score >= 70:
            verdict = "HIGH RISK - Likely Phishing"
        elif self.risk_score >= 40:
            verdict = "MEDIUM RISK - Suspicious"
        elif self.risk_score >= 20:
            verdict = "LOW RISK - Some Concerns"
        else:
            verdict = "MINIMAL RISK - Appears Legitimate"
        
        return {
            "risk_score": self.risk_score,
            "verdict": verdict,
            "indicators_count": len(self.indicators),
            "indicators": self.indicators
        }


# =============================================================================
# MAIN - DEMONSTRATION
# =============================================================================

def main():
    """
    Demonstrate all three SOC automation tools.
    """
    print("=" * 60)
    print("SOC AUTOMATION SCRIPTS - DEMONSTRATION")
    print("Author: Firebami Babalola")
    print("=" * 60)
    
    # Demo 1: IOC Enrichment
    print("\n[1] IOC ENRICHMENT DEMO")
    print("-" * 40)
    enricher = IOCEnricher()
    print("To use: enricher.check_ip('8.8.8.8')")
    print("Returns: IP reputation, country, malicious count")
    
    # Demo 2: Log Parser
    print("\n[2] WINDOWS LOG PARSER DEMO")
    print("-" * 40)
    parser = WindowsLogParser()
    print(f"Tracking {len(parser.SECURITY_EVENTS)} security event types")
    print("Key events: Failed Logon (4625), Admin Logon (4672), Audit Clear (1102)")
    
    # Demo 3: Phishing Analyzer
    print("\n[3] PHISHING ANALYZER DEMO")
    print("-" * 40)
    analyzer = PhishingAnalyzer()
    
    # Test with suspicious email
    test_headers = {
        "From": "security@amaz0n-support.xyz",
        "Reply-To": "hacker@gmail.com",
        "Subject": "URGENT: Your account has been suspended! Action Required!",
        "Received": "from unknown.server.xyz"
    }
    
    analyzer.analyze_headers(test_headers)
    result = analyzer.get_verdict()
    
    print(f"Test Email Analysis:")
    print(f"  Risk Score: {result['risk_score']}")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Indicators Found: {result['indicators_count']}")
    
    for indicator in result['indicators']:
        print(f"    - [{indicator['severity']}] {indicator['type']}: {indicator['detail']}")
    
    print("\n" + "=" * 60)
    print("All scripts ready for SOC automation tasks!")
    print("=" * 60)


if __name__ == "__main__":
    main()
