#!/usr/bin/env python3
"""
Agentic Red Team Vulnerability Detection Add-on for Splunk
Captures and indexes vulnerabilities detected during red team operations
"""

import os
import sys
import json
import time
import hashlib
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """Types of vulnerabilities detected"""
    RCE = "remote_code_execution"
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    AUTH_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEAK_CRYPTO = "weak_cryptography"
    EXPOSED_SECRETS = "exposed_secrets"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SSRF = "server_side_request_forgery"
    XXE = "xml_external_entity"
    PATH_TRAVERSAL = "path_traversal"
    WEAK_PERMISSIONS = "weak_file_permissions"
    UNPATCHED_SERVICE = "unpatched_service"
    DEFAULT_CREDENTIALS = "default_credentials"
    DATA_EXPOSURE = "sensitive_data_exposure"


class AgenticRedTeamAddon:
    """Main Splunk Add-on for Agentic Red Team vulnerability detection"""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.timestamp = datetime.utcnow()
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.session_id = self._generate_session_id()

    def _generate_session_id(self) -> str:
        """Generate unique session ID for this run"""
        timestamp = self.timestamp.isoformat()
        hostname = self.hostname
        random_data = os.urandom(8).hex()
        session_str = f"{timestamp}_{hostname}_{random_data}"
        return hashlib.sha256(session_str.encode()).hexdigest()[:16]

    def add_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        severity: VulnerabilitySeverity,
        target: str,
        description: str,
        cve_ids: Optional[List[str]] = None,
        affected_component: Optional[str] = None,
        remediation: Optional[str] = None,
        additional_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add a detected vulnerability to the list

        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
            target: Target of the vulnerability (IP, hostname, service, etc.)
            description: Description of the vulnerability
            cve_ids: Associated CVE IDs
            affected_component: Component affected by the vulnerability
            remediation: Recommended remediation steps
            additional_fields: Any additional custom fields
        """
        vuln_record = {
            "timestamp": self.timestamp.isoformat(),
            "event_type": "vulnerability_detection",
            "session_id": self.session_id,
            "vulnerability_type": vuln_type.value,
            "severity": severity.value,
            "target": target,
            "description": description,
            "cve_ids": cve_ids or [],
            "affected_component": affected_component or "Unknown",
            "remediation": remediation or "Manual review required",
            "hostname": self.hostname,
            "source": "agentic_red_team",
            "detection_timestamp": self.timestamp.isoformat(),
            "remediation_priority": self._calculate_priority(severity),
        }

        if additional_fields:
            vuln_record.update(additional_fields)

        self.vulnerabilities.append(vuln_record)

    def _calculate_priority(self, severity: VulnerabilitySeverity) -> int:
        """Calculate remediation priority (1-100)"""
        priority_map = {
            VulnerabilitySeverity.CRITICAL: 100,
            VulnerabilitySeverity.HIGH: 80,
            VulnerabilitySeverity.MEDIUM: 60,
            VulnerabilitySeverity.LOW: 40,
            VulnerabilitySeverity.INFO: 20,
        }
        return priority_map.get(severity, 50)

    def run_system_scans(self) -> None:
        """Execute system-level vulnerability scans"""
        self._scan_open_ports()
        self._scan_weak_permissions()
        self._scan_running_services()
        self._scan_network_exposure()
        self._scan_secrets()

    def _scan_open_ports(self) -> None:
        """Scan for unexpectedly open ports"""
        dangerous_ports = {
            23: ("Telnet", "Unencrypted remote access"),
            25: ("SMTP", "Possible open relay"),
            53: ("DNS", "Possible DNS amplification"),
            67: ("DHCP", "Possible DHCP spoofing"),
            69: ("TFTP", "Unencrypted file transfer"),
            135: ("RPC", "Remote procedure call exposure"),
            139: ("NetBIOS", "Windows file sharing exposure"),
            161: ("SNMP", "Unencrypted monitoring protocol"),
            389: ("LDAP", "Unencrypted directory service"),
            445: ("SMB", "Windows file sharing vulnerability"),
            1433: ("MSSQL", "Database exposure"),
            3306: ("MySQL", "Database exposure"),
            5432: ("PostgreSQL", "Database exposure"),
            5984: ("CouchDB", "NoSQL database exposure"),
            6379: ("Redis", "In-memory database exposure"),
            9200: ("Elasticsearch", "Search engine exposure"),
            27017: ("MongoDB", "NoSQL database exposure"),
        }

        for port, (service, risk) in dangerous_ports.items():
            # Simulate port scanning results
            if self._is_port_exposed(port):
                self.add_vulnerability(
                    vuln_type=VulnerabilityType.UNPATCHED_SERVICE,
                    severity=VulnerabilitySeverity.CRITICAL,
                    target=f"{self.hostname}:{port}",
                    description=f"{service} service exposed on port {port}",
                    affected_component=service,
                    remediation=f"Restrict network access to port {port} or disable if not needed",
                    additional_fields={
                        "port": port,
                        "service_name": service,
                        "risk_description": risk,
                    },
                )

    def _scan_weak_permissions(self) -> None:
        """Scan for weak file permissions"""
        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh",
            "/home/*/.ssh/id_rsa",
            "/var/www/.env",
            "/opt/app/config.json",
        ]

        for path_pattern in sensitive_paths:
            if self._has_weak_permissions(path_pattern):
                self.add_vulnerability(
                    vuln_type=VulnerabilityType.WEAK_PERMISSIONS,
                    severity=VulnerabilitySeverity.HIGH,
                    target=path_pattern,
                    description=f"Sensitive file has weak permissions: {path_pattern}",
                    affected_component="File System",
                    remediation="Set appropriate file permissions (chmod 600 or 700)",
                    additional_fields={
                        "file_path": path_pattern,
                        "current_permissions": "0644",
                        "recommended_permissions": "0600",
                    },
                )

    def _scan_running_services(self) -> None:
        """Scan for vulnerable running services"""
        vulnerable_services = [
            {
                "name": "Apache 2.2",
                "version": "2.2.15",
                "cves": ["CVE-2011-3607", "CVE-2011-3192"],
                "severity": VulnerabilitySeverity.HIGH,
            },
            {
                "name": "OpenSSH",
                "version": "5.1",
                "cves": ["CVE-2008-4109"],
                "severity": VulnerabilitySeverity.MEDIUM,
            },
            {
                "name": "PHP",
                "version": "5.2.0",
                "cves": ["CVE-2012-0830", "CVE-2012-1823"],
                "severity": VulnerabilitySeverity.CRITICAL,
            },
        ]

        for service in vulnerable_services:
            if self._is_service_running(service["name"]):
                self.add_vulnerability(
                    vuln_type=VulnerabilityType.UNPATCHED_SERVICE,
                    severity=service["severity"],
                    target=f"{self.hostname}:{service['name']}",
                    description=f"Unpatched service detected: {service['name']} v{service['version']}",
                    cve_ids=service["cves"],
                    affected_component=service["name"],
                    remediation=f"Update {service['name']} to the latest patched version",
                    additional_fields={
                        "service_name": service["name"],
                        "current_version": service["version"],
                        "vulnerability_count": len(service["cves"]),
                    },
                )

    def _scan_network_exposure(self) -> None:
        """Scan for network exposure and SSRF vulnerabilities"""
        exposed_endpoints = [
            {
                "url": "http://localhost:8080/admin",
                "type": VulnerabilityType.AUTH_BYPASS,
                "severity": VulnerabilitySeverity.CRITICAL,
                "reason": "Admin panel accessible without authentication",
            },
            {
                "url": "http://169.254.169.254/latest/meta-data",
                "type": VulnerabilityType.SSRF,
                "severity": VulnerabilitySeverity.CRITICAL,
                "reason": "AWS metadata endpoint accessible (SSRF vector)",
            },
            {
                "url": "http://localhost:6379",
                "type": VulnerabilityType.UNPATCHED_SERVICE,
                "severity": VulnerabilitySeverity.CRITICAL,
                "reason": "Redis instance with no authentication",
            },
        ]

        for endpoint in exposed_endpoints:
            if self._endpoint_responds(endpoint["url"]):
                self.add_vulnerability(
                    vuln_type=endpoint["type"],
                    severity=endpoint["severity"],
                    target=endpoint["url"],
                    description=endpoint["reason"],
                    affected_component="Network Service",
                    remediation="Restrict network access or implement authentication",
                    additional_fields={
                        "endpoint_url": endpoint["url"],
                        "http_method": "GET",
                        "response_code": 200,
                    },
                )

    def _scan_secrets(self) -> None:
        """Scan for exposed secrets"""
        secret_patterns = [
            {
                "pattern": "api_key",
                "severity": VulnerabilitySeverity.CRITICAL,
                "locations": [".env", "config.json", "app.properties"],
            },
            {
                "pattern": "database_password",
                "severity": VulnerabilitySeverity.CRITICAL,
                "locations": [".env", "docker-compose.yml"],
            },
            {
                "pattern": "private_key",
                "severity": VulnerabilitySeverity.CRITICAL,
                "locations": [".ssh", ".pem", "keys/"],
            },
        ]

        for secret in secret_patterns:
            if self._secret_found(secret["pattern"]):
                self.add_vulnerability(
                    vuln_type=VulnerabilityType.EXPOSED_SECRETS,
                    severity=secret["severity"],
                    target="Configuration Files",
                    description=f"Exposed secret detected: {secret['pattern']}",
                    affected_component="Application Configuration",
                    remediation="Move secrets to secure vault (HashiCorp Vault, AWS Secrets Manager, etc.)",
                    additional_fields={
                        "secret_type": secret["pattern"],
                        "found_in": secret["locations"],
                        "exposure_method": "File System",
                    },
                )

    def _is_port_exposed(self, port: int) -> bool:
        """Simulate port exposure check"""
        exposed_ports = [22, 23, 25, 53, 3306, 5432, 6379, 27017, 9200]
        return port in exposed_ports

    def _has_weak_permissions(self, path: str) -> bool:
        """Simulate weak permission check"""
        weak_permission_paths = ["/etc/passwd", "/root/.ssh", "/var/www/.env"]
        return any(path.startswith(p) for p in weak_permission_paths)

    def _is_service_running(self, service_name: str) -> bool:
        """Simulate service running check"""
        running_services = ["Apache 2.2", "OpenSSH", "PHP"]
        return service_name in running_services

    def _endpoint_responds(self, url: str) -> bool:
        """Simulate endpoint availability check"""
        responding_endpoints = [
            "http://localhost:8080/admin",
            "http://169.254.169.254/latest/meta-data",
        ]
        return url in responding_endpoints

    def _secret_found(self, pattern: str) -> bool:
        """Simulate secret detection"""
        detected_secrets = ["api_key", "database_password", "private_key"]
        return pattern in detected_secrets

    def generate_splunk_events(self) -> List[str]:
        """Generate Splunk-formatted events from vulnerabilities"""
        splunk_events = []
        for vuln in self.vulnerabilities:
            event = self._format_as_splunk_event(vuln)
            splunk_events.append(event)
        return splunk_events

    def _format_as_splunk_event(self, vuln: Dict[str, Any]) -> str:
        """Format vulnerability as a Splunk event"""
        timestamp = int(datetime.fromisoformat(vuln["timestamp"]).timestamp())
        json_data = json.dumps(vuln)
        return f"{timestamp} {json_data}"

    def output_to_splunk(self, events: List[str]) -> None:
        """Output events to Splunk via stdout (HEC input would be standard)"""
        for event in events:
            print(event)

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Generate summary statistics of detected vulnerabilities"""
        if not self.vulnerabilities:
            return {}

        severity_count = {}
        type_count = {}
        high_priority_count = 0

        for vuln in self.vulnerabilities:
            severity = vuln["severity"]
            vuln_type = vuln["vulnerability_type"]

            severity_count[severity] = severity_count.get(severity, 0) + 1
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1

            if vuln["remediation_priority"] >= 80:
                high_priority_count += 1

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": severity_count,
            "by_type": type_count,
            "high_priority_count": high_priority_count,
            "session_id": self.session_id,
            "scan_timestamp": self.timestamp.isoformat(),
        }


def main():
    """Main entry point for the Splunk Add-on"""
    addon = AgenticRedTeamAddon()

    # Run all vulnerability scans
    addon.run_system_scans()

    # Add custom vulnerability examples
    addon.add_vulnerability(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        target="192.168.1.100:8080/api/users",
        description="SQL Injection vulnerability in user search endpoint",
        cve_ids=["CVE-2024-1234"],
        affected_component="User API Endpoint",
        remediation="Implement parameterized queries and input validation",
        additional_fields={
            "endpoint": "/api/users?search=",
            "vulnerable_parameter": "search",
            "injection_payload": "'; DROP TABLE users; --",
        },
    )

    addon.add_vulnerability(
        vuln_type=VulnerabilityType.RCE,
        severity=VulnerabilitySeverity.CRITICAL,
        target="192.168.1.101:9200",
        description="Unauthenticated remote code execution in Elasticsearch",
        cve_ids=["CVE-2023-5678"],
        affected_component="Elasticsearch Service",
        remediation="Update to patched version and enable authentication",
        additional_fields={
            "service": "Elasticsearch",
            "version": "7.10.0",
            "exploit_available": True,
            "proof_of_concept": "curl -X POST http://target:9200/_xpack/sql",
        },
    )

    addon.add_vulnerability(
        vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
        severity=VulnerabilitySeverity.HIGH,
        target=f"{addon.hostname}:/opt/application",
        description="Sudo misconfiguration allowing privilege escalation",
        affected_component="System Configuration",
        remediation="Review sudoers file and remove unnecessary NOPASSWD entries",
        additional_fields={
            "sudoers_entry": "www-data ALL=(ALL) NOPASSWD: /usr/local/bin/backup.sh",
            "privilege_level": "root",
            "exploitation_difficulty": "trivial",
        },
    )

    addon.add_vulnerability(
        vuln_type=VulnerabilityType.DEFAULT_CREDENTIALS,
        severity=VulnerabilitySeverity.HIGH,
        target="192.168.1.50:22",
        description="Default credentials detected on SSH service",
        affected_component="SSH Service",
        remediation="Change default credentials immediately",
        additional_fields={
            "service": "SSH",
            "default_user": "admin",
            "default_password": "password123",
        },
    )

    # Generate and output Splunk events
    events = addon.generate_splunk_events()
    addon.output_to_splunk(events)

    # Output summary statistics
    summary = addon.get_summary_statistics()
    print(f"# Summary: {json.dumps(summary)}", file=sys.stderr)


if __name__ == "__main__":
    main()
