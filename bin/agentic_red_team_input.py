#!/usr/bin/env python3
"""
FAZE Agentic Red Team Input Generator
Generates synthetic vulnerability logs in Splunk format
"""

import os
import sys
import json
import time
import random
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum

sys.path.insert(0, str(Path(__file__).parent))

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    RCE = "Remote Code Execution"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    AUTH_BYPASS = "Authentication Bypass"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    WEAK_CRYPTO = "Weak Cryptography"
    EXPOSED_SECRETS = "Exposed Secrets"
    MISCONFIGURATION = "Misconfiguration"
    UNPATCHED = "Unpatched Service"
    DEFAULT_CREDS = "Default Credentials"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    WEAK_SSL = "Weak SSL/TLS"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    LDAP_INJECTION = "LDAP Injection"
    XXE = "XML External Entity"


class SeverityLevel(Enum):
    """Severity levels"""
    CRITICAL = ("critical", 9.0, 10.0)
    HIGH = ("high", 7.0, 8.9)
    MEDIUM = ("medium", 4.0, 6.9)
    LOW = ("low", 0.1, 3.9)
    INFO = ("info", 0.0, 0.1)

    def __init__(self, label, cvss_min, cvss_max):
        self.label = label
        self.cvss_min = cvss_min
        self.cvss_max = cvss_max


class RedTeamVulnerabilityGenerator:
    """Generate red team vulnerability logs"""

    def __init__(self):
        self.session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        self.targets = [
            "prod.example.com",
            "api.example.com",
            "app.example.com",
            "10.0.1.5",
            "192.168.1.100",
        ]
        self.services = [
            "Apache/2.4.49",
            "Nginx/1.19.0",
            "PostgreSQL/11",
            "MySQL/5.7",
            "MongoDB/4.4",
            "Docker",
            "Kubernetes",
            "Jenkins",
        ]

    def generate_vulnerability(self, target: str = None, severity: SeverityLevel = None):
        """Generate a single vulnerability"""
        if target is None:
            target = random.choice(self.targets)
        if severity is None:
            severity = random.choice(list(SeverityLevel))

        vuln_type = random.choice(list(VulnerabilityType))
        cvss_score = round(
            random.uniform(severity.cvss_min, severity.cvss_max), 1
        )

        timestamp = datetime.utcnow() - timedelta(
            minutes=random.randint(0, 1440)
        )

        event = {
            "timestamp": timestamp.isoformat() + "Z",
            "sourcetype": "agentic:red_team:vulnerability",
            "source": "faze_red_team",
            "host": target,
            "vulnerability_id": f"vuln_{int(time.time())}_{random.randint(1000, 9999)}",
            "type": vuln_type.name,
            "title": vuln_type.value,
            "description": f"Found {vuln_type.value} on {target}",
            "target": target,
            "severity": severity.label,
            "cvss_score": cvss_score,
            "cvss_vector": self._generate_cvss_vector(severity),
            "service": random.choice(self.services),
            "cve_id": f"CVE-{random.randint(2010, 2024)}-{random.randint(10000, 99999)}",
            "remediation": f"Apply security patch for {random.choice(self.services)}",
            "fix_available": random.choice([True, True, True, False]),
            "session_id": self.session_id,
            "scan_type": random.choice(["full", "incremental", "targeted"]),
            "asset_type": random.choice(["web_server", "database", "api", "container"]),
            "risk_score": int(cvss_score * 10),
            "_time": int(timestamp.timestamp()),
        }

        return event

    def _generate_cvss_vector(self, severity: SeverityLevel) -> str:
        """Generate a CVSS vector string"""
        av = random.choice(["N", "A", "L"])
        au = random.choice(["N", "S", "M"])
        c = random.choice(["C", "P", "N"])
        i = random.choice(["C", "P", "N"])
        a = random.choice(["C", "P", "N"])
        return f"AV:{av}/AU:{au}/C:{c}/I:{i}/A:{a}"

    def generate_batch(self, count: int = 10):
        """Generate batch of vulnerabilities"""
        events = []
        for _ in range(count):
            events.append(self.generate_vulnerability())
        return events

    def output_events(self, events: list):
        """Output events in Splunk format"""
        for event in events:
            print(json.dumps(event))

    def output_summary(self, events: list):
        """Print summary of generated events"""
        print("\n" + "=" * 80)
        print("📊 VULNERABILITY SCAN SUMMARY")
        print("=" * 80)
        print(f"Session ID: {self.session_id}")
        print(f"Total Vulnerabilities: {len(events)}")

        # Breakdown by severity
        by_severity = {}
        for event in events:
            severity = event.get("severity")
            by_severity[severity] = by_severity.get(severity, 0) + 1

        print("\nBy Severity:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")

        # Breakdown by type
        by_type = {}
        for event in events:
            vuln_type = event.get("type")
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        print("\nTop Vulnerability Types:")
        sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_types[:5]:
            print(f"  {vuln_type}: {count}")

        # Critical vulnerabilities
        critical = [e for e in events if e.get("severity") == "critical"]
        if critical:
            print(f"\n🚨 CRITICAL VULNERABILITIES ({len(critical)}):")
            for event in critical[:3]:
                print(
                    f"  - {event['title']} on {event['target']} (CVSS: {event['cvss_score']})"
                )

        print("\n" + "=" * 80)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Generate red team vulnerability logs")
    parser.add_argument(
        "--count", type=int, default=10, help="Number of vulnerabilities to generate"
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    parser.add_argument(
        "--target", help="Specific target to scan"
    )
    parser.add_argument(
        "--summary", action="store_true", help="Show summary instead of raw events"
    )

    args = parser.parse_args()

    generator = RedTeamVulnerabilityGenerator()

    # Generate vulnerabilities
    events = []
    severity_filter = None
    if args.severity:
        severity_filter = SeverityLevel[args.severity.upper()]

    for _ in range(args.count):
        event = generator.generate_vulnerability(
            target=args.target, severity=severity_filter
        )
        events.append(event)

    # Output
    if args.summary:
        generator.output_summary(events)
    else:
        generator.output_events(events)


if __name__ == "__main__":
    main()
