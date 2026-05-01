#!/usr/bin/env python3
"""
Email Analyzer - Comprehensive email header analysis for phishing investigations.

Features:
- Parse email headers from .eml, .msg, or raw text
- Authentication validation (SPF, DKIM, DMARC)
- Routing path analysis
- IOC extraction from headers and body
- Suspicion scoring
- Attachment handling

Author: Firebami Babalola
License: MIT
"""

import argparse
import email
import email.policy
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import base64


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AuthResult:
    """Email authentication result."""
    mechanism: str  # SPF, DKIM, DMARC
    result: str     # pass, fail, softfail, neutral, none, temperror, permerror
    details: str = ""


@dataclass 
class RoutingHop:
    """Single hop in email routing path."""
    hop_number: int
    from_server: str
    by_server: str
    ip_address: Optional[str]
    timestamp: Optional[str]
    protocol: Optional[str]


@dataclass
class Attachment:
    """Email attachment info."""
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class EmailAnalysis:
    """Complete email analysis result."""
    # Basic headers
    subject: str = ""
    from_address: str = ""
    from_display_name: str = ""
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)
    reply_to: str = ""
    date: str = ""
    message_id: str = ""
    
    # Authentication
    auth_results: List[AuthResult] = field(default_factory=list)
    
    # Routing
    routing_path: List[RoutingHop] = field(default_factory=list)
    originating_ip: str = ""
    
    # IOCs
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    
    # Attachments
    attachments: List[Attachment] = field(default_factory=list)
    
    # Suspicion analysis
    suspicion_score: int = 0
    suspicion_reasons: List[str] = field(default_factory=list)
    
    # Raw data
    all_headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_html: str = ""
    
    # Metadata
    analyzed_at: str = ""
    source_file: str = ""


# =============================================================================
# EMAIL ANALYZER
# =============================================================================

class EmailAnalyzer:
    """
    Analyze email headers and content for security investigation.
    """
    
    # Regex patterns
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    
    # Suspicious patterns
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
        '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.ps1', '.msi',
        '.msp', '.hta', '.cpl', '.jar', '.dll', '.lnk', '.iso', '.img'
    }
    
    SUSPICIOUS_CONTENT_TYPES = {
        'application/x-msdownload',
        'application/x-executable',
        'application/x-dosexec',
        'application/hta',
        'application/x-msdos-program'
    }
    
    URGENCY_WORDS = {
        'urgent', 'immediately', 'action required', 'account suspended',
        'verify your', 'confirm your', 'update your', 'expire', 'expired',
        'suspended', 'compromised', 'unauthorized', 'security alert',
        'unusual activity', 'verify identity', 'click here', 'act now'
    }
    
    def __init__(self):
        self.analysis = EmailAnalysis()
    
    def analyze_file(self, file_path: Path) -> EmailAnalysis:
        """Analyze email from file."""
        self.analysis = EmailAnalysis(
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            source_file=str(file_path)
        )
        
        # Read and parse email
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        self._analyze_message(msg)
        return self.analysis
    
    def analyze_raw(self, raw_email: str) -> EmailAnalysis:
        """Analyze email from raw string."""
        self.analysis = EmailAnalysis(
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            source_file="raw_input"
        )
        
        msg = Parser(policy=policy.default).parsestr(raw_email)
        self._analyze_message(msg)
        return self.analysis
    
    def _analyze_message(self, msg: email.message.Message):
        """Main analysis logic."""
        # Extract basic headers
        self._extract_basic_headers(msg)
        
        # Parse authentication results
        self._parse_authentication(msg)
        
        # Trace routing path
        self._trace_routing(msg)
        
        # Extract IOCs
        self._extract_iocs(msg)
        
        # Process attachments
        self._process_attachments(msg)
        
        # Calculate suspicion score
        self._calculate_suspicion()
        
        # Store all headers
        for key in msg.keys():
            self.analysis.all_headers[key] = str(msg.get(key, ''))
    
    def _extract_basic_headers(self, msg: email.message.Message):
        """Extract basic email headers."""
        # Subject
        self.analysis.subject = str(msg.get('Subject', ''))
        
        # From
        from_header = msg.get('From', '')
        if from_header:
            # Parse display name and email
            match = re.match(r'(?:"?([^"]*)"?\s*)?<?([^>]+@[^>]+)>?', str(from_header))
            if match:
                self.analysis.from_display_name = match.group(1) or ''
                self.analysis.from_address = match.group(2) or str(from_header)
            else:
                self.analysis.from_address = str(from_header)
        
        # To
        to_header = msg.get('To', '')
        if to_header:
            self.analysis.to_addresses = self._extract_emails(str(to_header))
        
        # CC
        cc_header = msg.get('Cc', '')
        if cc_header:
            self.analysis.cc_addresses = self._extract_emails(str(cc_header))
        
        # Reply-To
        self.analysis.reply_to = str(msg.get('Reply-To', ''))
        
        # Date
        self.analysis.date = str(msg.get('Date', ''))
        
        # Message-ID
        self.analysis.message_id = str(msg.get('Message-ID', ''))
        
        # Extract body
        self._extract_body(msg)
    
    def _extract_emails(self, header: str) -> List[str]:
        """Extract email addresses from header."""
        pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        return pattern.findall(header)
    
    def _extract_body(self, msg: email.message.Message):
        """Extract email body (plain text and HTML)."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        self.analysis.body_text = payload.decode('utf-8', errors='replace')
                elif content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        self.analysis.body_html = payload.decode('utf-8', errors='replace')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == 'text/html':
                    self.analysis.body_html = payload.decode('utf-8', errors='replace')
                else:
                    self.analysis.body_text = payload.decode('utf-8', errors='replace')
    
    def _parse_authentication(self, msg: email.message.Message):
        """Parse authentication results (SPF, DKIM, DMARC)."""
        auth_results_header = str(msg.get('Authentication-Results', ''))
        
        if not auth_results_header:
            return
        
        # Parse SPF
        spf_match = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', auth_results_header, re.IGNORECASE)
        if spf_match:
            self.analysis.auth_results.append(AuthResult(
                mechanism='SPF',
                result=spf_match.group(1).lower(),
                details=spf_match.group(2) or ''
            ))
        
        # Parse DKIM
        dkim_match = re.search(r'dkim=(\w+)(?:\s+\(([^)]+)\))?', auth_results_header, re.IGNORECASE)
        if dkim_match:
            self.analysis.auth_results.append(AuthResult(
                mechanism='DKIM',
                result=dkim_match.group(1).lower(),
                details=dkim_match.group(2) or ''
            ))
        
        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(\w+)(?:\s+\(([^)]+)\))?', auth_results_header, re.IGNORECASE)
        if dmarc_match:
            self.analysis.auth_results.append(AuthResult(
                mechanism='DMARC',
                result=dmarc_match.group(1).lower(),
                details=dmarc_match.group(2) or ''
            ))
    
    def _trace_routing(self, msg: email.message.Message):
        """Trace email routing path from Received headers."""
        received_headers = msg.get_all('Received', [])
        
        hop_num = len(received_headers)
        for header in received_headers:
            header_str = str(header)
            
            hop = RoutingHop(
                hop_number=hop_num,
                from_server='',
                by_server='',
                ip_address=None,
                timestamp=None,
                protocol=None
            )
            
            # Extract "from" server
            from_match = re.search(r'from\s+([^\s\(]+)', header_str, re.IGNORECASE)
            if from_match:
                hop.from_server = from_match.group(1)
            
            # Extract "by" server
            by_match = re.search(r'by\s+([^\s\(]+)', header_str, re.IGNORECASE)
            if by_match:
                hop.by_server = by_match.group(1)
            
            # Extract IP address
            ip_match = self.IP_PATTERN.search(header_str)
            if ip_match:
                hop.ip_address = ip_match.group()
                if hop_num == len(received_headers):
                    self.analysis.originating_ip = hop.ip_address
            
            # Extract timestamp
            # Common formats: ; Tue, 30 Apr 2026 10:15:00 -0400
            time_match = re.search(r';\s*(.+)$', header_str)
            if time_match:
                hop.timestamp = time_match.group(1).strip()
            
            # Extract protocol
            proto_match = re.search(r'with\s+(\w+)', header_str, re.IGNORECASE)
            if proto_match:
                hop.protocol = proto_match.group(1)
            
            self.analysis.routing_path.append(hop)
            hop_num -= 1
        
        # Reverse to show oldest first
        self.analysis.routing_path.reverse()
    
    def _extract_iocs(self, msg: email.message.Message):
        """Extract IOCs from headers and body."""
        # Combine all text sources
        all_text = str(msg)
        if self.analysis.body_text:
            all_text += '\n' + self.analysis.body_text
        if self.analysis.body_html:
            all_text += '\n' + self.analysis.body_html
        
        # Extract IPs (excluding common internal ranges)
        ips = self.IP_PATTERN.findall(all_text)
        ips = list(set(ips))
        # Filter internal IPs
        ips = [ip for ip in ips if not ip.startswith(('10.', '192.168.', '127.', '0.'))]
        self.analysis.ips = ips
        
        # Extract domains
        domains = self.DOMAIN_PATTERN.findall(all_text.lower())
        domains = list(set(domains))
        # Filter common false positives
        domains = [d for d in domains if not d.endswith(('.png', '.jpg', '.gif', '.css', '.js'))]
        self.analysis.domains = domains
        
        # Extract URLs
        urls = self.URL_PATTERN.findall(all_text)
        urls = list(set(urls))
        self.analysis.urls = urls
    
    def _process_attachments(self, msg: email.message.Message):
        """Process and hash email attachments."""
        if not msg.is_multipart():
            return
        
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            if 'attachment' not in content_disposition and 'inline' not in content_disposition:
                continue
            
            filename = part.get_filename() or 'unknown'
            content_type = part.get_content_type()
            
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            
            # Calculate hashes
            md5_hash = hashlib.md5(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()
            
            # Check for suspicious characteristics
            is_suspicious = False
            suspicion_reason = ''
            
            # Check extension
            filename_lower = filename.lower()
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if filename_lower.endswith(ext):
                    is_suspicious = True
                    suspicion_reason = f'Suspicious extension: {ext}'
                    break
            
            # Check content type
            if content_type.lower() in self.SUSPICIOUS_CONTENT_TYPES:
                is_suspicious = True
                suspicion_reason = f'Suspicious content type: {content_type}'
            
            # Check for double extension
            if re.search(r'\.(pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|bat|cmd|vbs|js)', 
                        filename_lower):
                is_suspicious = True
                suspicion_reason = 'Double extension detected'
            
            attachment = Attachment(
                filename=filename,
                content_type=content_type,
                size=len(payload),
                md5=md5_hash,
                sha256=sha256_hash,
                is_suspicious=is_suspicious,
                suspicion_reason=suspicion_reason
            )
            
            self.analysis.attachments.append(attachment)
    
    def _calculate_suspicion(self):
        """Calculate overall suspicion score."""
        score = 0
        reasons = []
        
        # Check authentication failures
        for auth in self.analysis.auth_results:
            if auth.result in ('fail', 'softfail', 'permerror'):
                score += 15
                reasons.append(f'{auth.mechanism} {auth.result}')
        
        # Check Reply-To mismatch
        if self.analysis.reply_to:
            reply_domain = self._extract_domain(self.analysis.reply_to)
            from_domain = self._extract_domain(self.analysis.from_address)
            if reply_domain and from_domain and reply_domain != from_domain:
                score += 20
                reasons.append('Reply-To domain differs from From domain')
        
        # Check for typosquatting patterns in From address
        from_domain = self._extract_domain(self.analysis.from_address)
        if from_domain:
            # Common brands
            typosquat_patterns = [
                (r'paypa[l1]', 'paypal'),
                (r'app[l1]e', 'apple'),
                (r'amaz[o0]n', 'amazon'),
                (r'g[o0][o0]gle', 'google'),
                (r'micr[o0]s[o0]ft', 'microsoft'),
                (r'faceb[o0][o0]k', 'facebook'),
                (r'netf[l1]ix', 'netflix'),
            ]
            for pattern, brand in typosquat_patterns:
                if re.search(pattern, from_domain, re.IGNORECASE) and brand not in from_domain.lower():
                    score += 25
                    reasons.append(f'Possible typosquatting: {from_domain}')
                    break
        
        # Check subject for urgency
        subject_lower = self.analysis.subject.lower()
        for word in self.URGENCY_WORDS:
            if word in subject_lower:
                score += 10
                reasons.append(f'Urgency language in subject: "{word}"')
                break
        
        # Check body for urgency
        body = (self.analysis.body_text + ' ' + self.analysis.body_html).lower()
        urgency_count = sum(1 for word in self.URGENCY_WORDS if word in body)
        if urgency_count >= 3:
            score += 15
            reasons.append(f'Multiple urgency phrases in body ({urgency_count})')
        
        # Check for suspicious attachments
        for attachment in self.analysis.attachments:
            if attachment.is_suspicious:
                score += 25
                reasons.append(f'Suspicious attachment: {attachment.filename}')
        
        # Check for external links in HTML
        if self.analysis.body_html:
            external_links = len(re.findall(r'href=["\']https?://', self.analysis.body_html))
            if external_links > 10:
                score += 10
                reasons.append(f'Many external links ({external_links})')
        
        # Cap at 100
        self.analysis.suspicion_score = min(score, 100)
        self.analysis.suspicion_reasons = reasons
    
    def _extract_domain(self, email_or_url: str) -> Optional[str]:
        """Extract domain from email or URL."""
        # From email
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_or_url)
        if match:
            return match.group(1).lower()
        
        # From URL
        match = re.search(r'://([a-zA-Z0-9.-]+)', email_or_url)
        if match:
            return match.group(1).lower()
        
        return None


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

def format_text(analysis: EmailAnalysis) -> str:
    """Format analysis as human-readable text."""
    lines = []
    
    # Header box
    lines.append("╔" + "═" * 70 + "╗")
    lines.append("║" + "EMAIL ANALYSIS REPORT".center(70) + "║")
    lines.append("╠" + "═" * 70 + "╣")
    
    # Basic info
    lines.append(f"║ Subject: {analysis.subject[:60]:<60} ║")
    lines.append(f"║ From: {analysis.from_address[:62]:<62} ║")
    if analysis.from_display_name:
        lines.append(f"║   Display Name: {analysis.from_display_name[:54]:<54} ║")
    if analysis.reply_to and analysis.reply_to != analysis.from_address:
        lines.append(f"║ Reply-To: {analysis.reply_to[:58]:<58} ║")
        lines.append(f"║   ⚠️  MISMATCH with From address" + " " * 35 + "║")
    lines.append(f"║ Date: {analysis.date[:62]:<62} ║")
    
    # Authentication
    lines.append("╠" + "═" * 70 + "╣")
    lines.append("║" + "AUTHENTICATION RESULTS".center(70) + "║")
    lines.append("╠" + "═" * 70 + "╣")
    
    if analysis.auth_results:
        for auth in analysis.auth_results:
            icon = "✅" if auth.result == "pass" else "❌"
            result_str = f"{auth.mechanism}: {icon} {auth.result.upper()}"
            if auth.details:
                result_str += f" ({auth.details[:40]})"
            lines.append(f"║ {result_str:<68} ║")
    else:
        lines.append("║" + "No authentication results found".center(70) + "║")
    
    # Routing
    lines.append("╠" + "═" * 70 + "╣")
    lines.append(f"║ ROUTING PATH ({len(analysis.routing_path)} hops)" + " " * 50 + "║")
    lines.append("╠" + "═" * 70 + "╣")
    
    for hop in analysis.routing_path[:5]:  # Show first 5 hops
        hop_str = f"{hop.hop_number}. {hop.from_server[:30]}"
        if hop.ip_address:
            hop_str += f" [{hop.ip_address}]"
        lines.append(f"║ {hop_str:<68} ║")
    
    if len(analysis.routing_path) > 5:
        lines.append(f"║ ... and {len(analysis.routing_path) - 5} more hops" + " " * 50 + "║")
    
    # Attachments
    if analysis.attachments:
        lines.append("╠" + "═" * 70 + "╣")
        lines.append(f"║ ATTACHMENTS ({len(analysis.attachments)})" + " " * 52 + "║")
        lines.append("╠" + "═" * 70 + "╣")
        
        for att in analysis.attachments:
            icon = "⚠️" if att.is_suspicious else "📎"
            att_str = f"{icon} {att.filename} ({att.size} bytes)"
            lines.append(f"║ {att_str:<68} ║")
            if att.is_suspicious:
                lines.append(f"║   ⚠️  {att.suspicion_reason:<62} ║")
    
    # Suspicion Score
    lines.append("╠" + "═" * 70 + "╣")
    
    risk_level = "LOW"
    if analysis.suspicion_score >= 50:
        risk_level = "MEDIUM"
    if analysis.suspicion_score >= 75:
        risk_level = "HIGH"
    
    score_str = f"⚠️  SUSPICION SCORE: {analysis.suspicion_score}/100 ({risk_level} RISK)"
    lines.append(f"║ {score_str:<68} ║")
    
    for reason in analysis.suspicion_reasons[:5]:
        lines.append(f"║   - {reason[:64]:<64} ║")
    
    lines.append("╚" + "═" * 70 + "╝")
    
    return "\n".join(lines)


def format_json(analysis: EmailAnalysis) -> str:
    """Format analysis as JSON."""
    output = {
        "subject": analysis.subject,
        "from": {
            "address": analysis.from_address,
            "display_name": analysis.from_display_name
        },
        "to": analysis.to_addresses,
        "cc": analysis.cc_addresses,
        "reply_to": analysis.reply_to,
        "date": analysis.date,
        "message_id": analysis.message_id,
        "authentication": [
            {"mechanism": a.mechanism, "result": a.result, "details": a.details}
            for a in analysis.auth_results
        ],
        "routing": [
            {
                "hop": h.hop_number,
                "from": h.from_server,
                "by": h.by_server,
                "ip": h.ip_address,
                "timestamp": h.timestamp
            }
            for h in analysis.routing_path
        ],
        "originating_ip": analysis.originating_ip,
        "iocs": {
            "ips": analysis.ips,
            "domains": analysis.domains,
            "urls": analysis.urls
        },
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size": a.size,
                "md5": a.md5,
                "sha256": a.sha256,
                "is_suspicious": a.is_suspicious,
                "suspicion_reason": a.suspicion_reason
            }
            for a in analysis.attachments
        ],
        "suspicion": {
            "score": analysis.suspicion_score,
            "reasons": analysis.suspicion_reasons
        },
        "metadata": {
            "analyzed_at": analysis.analyzed_at,
            "source_file": analysis.source_file
        }
    }
    
    return json.dumps(output, indent=2)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze email headers for phishing investigation."
    )
    
    parser.add_argument('--file', '-f', type=Path, required=True,
                        help='Email file to analyze (.eml, .msg, or raw text)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--output', '-o', type=Path,
                        help='Output file (default: stdout)')
    parser.add_argument('--headers-only', action='store_true',
                        help='Show only headers (no body analysis)')
    parser.add_argument('--extract-attachments', type=Path,
                        help='Extract attachments to directory')
    
    args = parser.parse_args()
    
    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    # Analyze
    analyzer = EmailAnalyzer()
    analysis = analyzer.analyze_file(args.file)
    
    # Format output
    if args.json:
        output = format_json(analysis)
    else:
        output = format_text(analysis)
    
    # Write output
    if args.output:
        args.output.write_text(output)
        print(f"Analysis written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
