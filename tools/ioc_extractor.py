#!/usr/bin/env python3
"""
IOC Extractor

Small command line tool for pulling indicators of compromise out of messy
security notes, phishing reports, and alert text.

I built this as a SOC automation practice project. The goal is simple:
make the boring part of triage faster without pretending this replaces a
SIEM, SOAR tool, EDR, or threat intel platform.

What it can do:
- pull common IOCs from text, files, stdin, or a URL
- handle common defanged values like hxxp:// and [.] domains
- print results as text, JSON, CSV, or a basic STIX-style bundle
- remove duplicates so the output is easier to review

Author: Firebami Babalola
License: MIT
"""

import argparse
import json
import re
import sys
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid


class IOCType(Enum):
    """The IOC categories this script knows how to look for."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SSDEEP = "ssdeep"
    CVE = "cve"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    MONERO = "monero"
    FILE_PATH_WIN = "file_path_win"
    FILE_PATH_UNIX = "file_path_unix"
    REGISTRY = "registry"
    YARA = "yara"
    MITRE_ATTACK = "mitre_attack"


@dataclass
class ExtractionResult:
    """Simple container for the results and a little metadata."""
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    source: str = ""
    extracted_at: str = ""
    total_count: int = 0
    defanged_count: int = 0
    duplicates_removed: int = 0
    errors: List[str] = field(default_factory=list)


class Patterns:
    """
    Regex patterns used by the extractor.

    These are intentionally readable. In a real SOC tool, I would tune these
    with more test data and false-positive examples before trusting them in a
    production workflow.
    """

    # Normalize common defanged values first so the regex patterns can catch them.
    DEFANG_REPLACEMENTS = [
        (r'hxxp', 'http'),
        (r'hXXp', 'http'),
        (r'HXXP', 'http'),
        (r'h__p', 'http'),
        (r'h\*\*p', 'http'),
        (r'\[\.\]', '.'),
        (r'\[dot\]', '.'),
        (r'\(dot\)', '.'),
        (r'\[DOT\]', '.'),
        (r'\(DOT\)', '.'),
        (r'\[ \. \]', '.'),
        (r' dot ', '.'),
        (r'\[@\]', '@'),
        (r'\[at\]', '@'),
        (r'\(at\)', '@'),
        (r'\[AT\]', '@'),
        (r' at ', '@'),
        (r'\[:\]', ':'),
        (r'\[colon\]', ':'),
        (r'\[/\]', '/'),
    ]

    IPV4 = re.compile(
        r'\b'
        r'(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
        r'\b'
    )

    IPV6 = re.compile(
        r'\b(?:'
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
        r':(?::[0-9a-fA-F]{1,4}){1,7}'
        r')\b'
    )

    TLDS = (
        r'com|net|org|edu|gov|mil|io|co|me|info|biz|xyz|online|site|tech|'
        r'cloud|app|dev|ru|cn|uk|de|jp|fr|au|in|br|it|nl|es|ca|mx|kr|pl|'
        r'se|ch|be|at|cz|dk|fi|gr|hu|ie|no|pt|ro|sk|ua|za|nz|sg|hk|tw'
    )

    DOMAIN = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:' + TLDS + r')\b',
        re.IGNORECASE
    )

    URL = re.compile(r'https?://[^\s<>"\')\]\}]+', re.IGNORECASE)
    EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
    SHA512 = re.compile(r'\b[a-fA-F0-9]{128}\b')
    SSDEEP = re.compile(r'\b\d+:[a-zA-Z0-9/+]+:[a-zA-Z0-9/+]+\b')
    CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    BITCOIN = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b')
    ETHEREUM = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    MONERO = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')
    FILE_PATH_WIN = re.compile(r'[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
    FILE_PATH_UNIX = re.compile(r'(?:/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+)')
    REGISTRY = re.compile(
        r'\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|'
        r'HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s"\'<>]+',
        re.IGNORECASE
    )
    MITRE_ATTACK = re.compile(r'\b(?:T[0-9]{4}(?:\.[0-9]{3})?|G[0-9]{4}|S[0-9]{4})\b')


class IOCExtractor:
    """Main extraction logic."""

    def __init__(self, refang: bool = True, dedupe: bool = True, validate: bool = True, include_private_ips: bool = False):
        self.refang = refang
        self.dedupe = dedupe
        self.validate = validate
        self.include_private_ips = include_private_ips

    def _refang_text(self, text: str) -> Tuple[str, int]:
        """Convert common defanged values back so they can be extracted."""
        count = 0
        result = text

        for pattern, replacement in Patterns.DEFANG_REPLACEMENTS:
            matches = len(re.findall(pattern, result, re.IGNORECASE))
            if matches:
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                count += matches

        return result, count

    def _validate_ipv4(self, ip: str) -> bool:
        """Validate IPv4 and optionally filter private/internal addresses."""
        try:
            addr = ipaddress.IPv4Address(ip)
            if not self.include_private_ips and (addr.is_private or addr.is_loopback or addr.is_reserved):
                return False
            return True
        except ipaddress.AddressValueError:
            return False

    def _validate_ipv6(self, ip: str) -> bool:
        """Validate IPv6 and optionally filter private/internal addresses."""
        try:
            addr = ipaddress.IPv6Address(ip)
            if not self.include_private_ips and (addr.is_private or addr.is_loopback or addr.is_reserved):
                return False
            return True
        except ipaddress.AddressValueError:
            return False

    def _validate_hash(self, hash_val: str) -> bool:
        """Skip hashes that are usually examples or empty-file hashes."""
        if len(set(hash_val.lower())) <= 2:
            return False

        false_positives = {
            'd41d8cd98f00b204e9800998ecf8427e',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        }
        return hash_val.lower() not in false_positives

    def _validate_domain(self, domain: str) -> bool:
        """Remove obvious placeholder domains."""
        if len(domain) < 4:
            return False

        false_positives = {'example.com', 'test.com', 'localhost.com', 'domain.com', 'email.com', 'website.com'}
        if domain.lower() in false_positives:
            return False

        return True

    def extract(self, text: str, source: str = "unknown", ioc_types: Optional[List[IOCType]] = None) -> ExtractionResult:
        """Extract IOCs from a block of text."""
        result = ExtractionResult(source=source, extracted_at=datetime.now(timezone.utc).isoformat())

        if self.refang:
            text, refang_count = self._refang_text(text)
            result.defanged_count = refang_count

        if ioc_types is None:
            ioc_types = list(IOCType)

        pattern_map = {
            IOCType.IPV4: (Patterns.IPV4, self._validate_ipv4),
            IOCType.IPV6: (Patterns.IPV6, self._validate_ipv6),
            IOCType.DOMAIN: (Patterns.DOMAIN, self._validate_domain),
            IOCType.URL: (Patterns.URL, None),
            IOCType.EMAIL: (Patterns.EMAIL, None),
            IOCType.MD5: (Patterns.MD5, self._validate_hash),
            IOCType.SHA1: (Patterns.SHA1, self._validate_hash),
            IOCType.SHA256: (Patterns.SHA256, self._validate_hash),
            IOCType.SHA512: (Patterns.SHA512, self._validate_hash),
            IOCType.CVE: (Patterns.CVE, None),
            IOCType.BITCOIN: (Patterns.BITCOIN, None),
            IOCType.ETHEREUM: (Patterns.ETHEREUM, None),
            IOCType.MONERO: (Patterns.MONERO, None),
            IOCType.FILE_PATH_WIN: (Patterns.FILE_PATH_WIN, None),
            IOCType.FILE_PATH_UNIX: (Patterns.FILE_PATH_UNIX, None),
            IOCType.REGISTRY: (Patterns.REGISTRY, None),
            IOCType.MITRE_ATTACK: (Patterns.MITRE_ATTACK, None),
        }

        for ioc_type in ioc_types:
            if ioc_type not in pattern_map:
                continue

            pattern, validator = pattern_map[ioc_type]
            matches = pattern.findall(text)

            if self.dedupe:
                original_count = len(matches)
                matches = list(dict.fromkeys(matches))
                result.duplicates_removed += original_count - len(matches)

            if self.validate and validator:
                matches = [match for match in matches if validator(match)]

            if matches:
                result.iocs[ioc_type.value] = matches
                result.total_count += len(matches)

        return result


class OutputFormatter:
    """Format extraction results for the terminal or a file."""

    @staticmethod
    def to_text(result: ExtractionResult, defang: bool = False) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("IOC EXTRACTION RESULTS")
        lines.append(f"Source: {result.source}")
        lines.append(f"Extracted: {result.extracted_at}")
        lines.append(f"Total IOCs: {result.total_count}")
        if result.defanged_count:
            lines.append(f"Defanged values normalized: {result.defanged_count}")
        if result.duplicates_removed:
            lines.append(f"Duplicates removed: {result.duplicates_removed}")
        lines.append("=" * 60)
        lines.append("")

        for ioc_type, iocs in result.iocs.items():
            lines.append(f"=== {ioc_type.upper()} ({len(iocs)}) ===")
            for ioc in iocs:
                if defang:
                    ioc = ioc.replace('.', '[.]').replace('http', 'hxxp')
                lines.append(f"  {ioc}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_json(result: ExtractionResult, indent: int = 2) -> str:
        output = {
            "metadata": {
                "source": result.source,
                "extracted_at": result.extracted_at,
                "total_count": result.total_count,
                "defanged_count": result.defanged_count,
                "duplicates_removed": result.duplicates_removed,
            },
            "iocs": result.iocs,
            "errors": result.errors,
        }
        return json.dumps(output, indent=indent)

    @staticmethod
    def to_csv(result: ExtractionResult) -> str:
        lines = ["type,value"]
        for ioc_type, iocs in result.iocs.items():
            for ioc in iocs:
                ioc_escaped = ioc.replace('"', '""')
                if ',' in ioc or '"' in ioc:
                    ioc_escaped = f'"{ioc_escaped}"'
                lines.append(f"{ioc_type},{ioc_escaped}")
        return "\n".join(lines)

    @staticmethod
    def to_stix(result: ExtractionResult) -> str:
        """Create a basic STIX-style bundle for the most common IOC types."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects = []

        stix_type_map = {
            "ipv4": "ipv4-addr:value",
            "ipv6": "ipv6-addr:value",
            "domain": "domain-name:value",
            "url": "url:value",
            "email": "email-addr:value",
            "md5": "file:hashes.MD5",
            "sha1": "file:hashes.'SHA-1'",
            "sha256": "file:hashes.'SHA-256'",
        }

        for ioc_type, iocs in result.iocs.items():
            if ioc_type not in stix_type_map:
                continue

            for ioc in iocs:
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": result.extracted_at,
                    "modified": result.extracted_at,
                    "pattern": f"[{stix_type_map[ioc_type]} = '{ioc}']",
                    "pattern_type": "stix",
                    "valid_from": result.extracted_at,
                    "labels": ["malicious-activity"],
                })

        return json.dumps({"type": "bundle", "id": bundle_id, "objects": objects}, indent=2)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract indicators of compromise from text.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file examples/sample_threat_report.txt
  %(prog)s --file examples/sample_threat_report.txt --json
  %(prog)s --file examples/sample_threat_report.txt --defang
  cat logs.txt | %(prog)s --stdin
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', type=Path, help='Input file to extract from')
    input_group.add_argument('--stdin', action='store_true', help='Read from stdin')
    input_group.add_argument('--text', '-t', type=str, help='Direct text input')
    input_group.add_argument('--url', '-u', type=str, help='URL to fetch and extract from')

    parser.add_argument('--output', '-o', type=Path, help='Output file. Defaults to the terminal.')
    parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    parser.add_argument('--csv', action='store_true', help='Output as CSV')
    parser.add_argument('--stix', action='store_true', help='Output as a basic STIX-style bundle')
    parser.add_argument('--type', dest='types', action='append', help='IOC type to extract. Can be repeated.')
    parser.add_argument('--no-refang', action='store_true', help='Do not normalize defanged IOCs first')
    parser.add_argument('--no-dedupe', action='store_true', help='Do not remove duplicates')
    parser.add_argument('--no-validate', action='store_true', help='Do not validate IOCs')
    parser.add_argument('--include-private', action='store_true', help='Include private/internal IP addresses')
    parser.add_argument('--defang', action='store_true', help='Defang IOCs in terminal output')

    return parser.parse_args()


def read_input(args: argparse.Namespace) -> Tuple[str, str]:
    """Read text from whichever input source the user picked."""
    if args.file:
        if not args.file.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        return args.file.read_text(encoding='utf-8', errors='replace'), str(args.file)

    if args.stdin:
        return sys.stdin.read(), "stdin"

    if args.text:
        return args.text, "cli"

    if args.url:
        try:
            import urllib.request
            with urllib.request.urlopen(args.url, timeout=30) as response:
                return response.read().decode('utf-8', errors='replace'), args.url
        except Exception as error:
            print(f"Error fetching URL: {error}", file=sys.stderr)
            sys.exit(1)

    print("Error: no input provided", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    args = parse_args()
    text, source = read_input(args)

    ioc_types = None
    if args.types:
        try:
            ioc_types = [IOCType(item.lower()) for item in args.types]
        except ValueError as error:
            print(f"Error: invalid IOC type: {error}", file=sys.stderr)
            print(f"Valid types: {', '.join(item.value for item in IOCType)}", file=sys.stderr)
            sys.exit(1)

    extractor = IOCExtractor(
        refang=not args.no_refang,
        dedupe=not args.no_dedupe,
        validate=not args.no_validate,
        include_private_ips=args.include_private,
    )
    result = extractor.extract(text, source=source, ioc_types=ioc_types)

    if args.stix:
        output = OutputFormatter.to_stix(result)
    elif args.json:
        output = OutputFormatter.to_json(result)
    elif args.csv:
        output = OutputFormatter.to_csv(result)
    else:
        output = OutputFormatter.to_text(result, defang=args.defang)

    if args.output:
        args.output.write_text(output, encoding='utf-8')
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output)

    sys.exit(0 if result.total_count > 0 else 1)


if __name__ == "__main__":
    main()
