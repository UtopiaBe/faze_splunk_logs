#!/usr/bin/env python3
"""
FAZE Security API Integration for Splunk
Fetches real vulnerabilities from FAZE Agentic Red Team platform
"""

import os
import sys
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class SeverityLevel(Enum):
    """FAZE severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FAZESecurityAddon:
    """FAZE Security API integration for Splunk"""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize FAZE addon with API key"""
        self.api_key = api_key or os.getenv("FAZE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "FAZE_API_KEY not provided. Set via parameter or FAZE_API_KEY environment variable"
            )

        self.base_url = os.getenv("FAZE_API_URL", "https://api.faze.security")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Splunk-FAZE-AddOn/2.0"
        })
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.scan_timestamp = datetime.utcnow()

    def get_assets(self, art_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch assets from FAZE

        Args:
            art_id: Optional asset/report ID to filter

        Returns:
            List of assets with vulnerability data
        """
        try:
            endpoint = f"{self.base_url}/GetAssets"
            payload = {}
            if art_id:
                payload["art_id"] = art_id

            response = self.session.post(
                endpoint,
                json=payload,
                timeout=30
            )
            response.raise_for_status()

            assets = response.json()
            return assets if isinstance(assets, list) else [assets]

        except requests.exceptions.RequestException as e:
            print(f"Error fetching assets from FAZE: {e}", file=sys.stderr)
            return []

    def get_vulnerabilities(self, asset_id: str) -> List[Dict[str, Any]]:
        """
        Fetch vulnerabilities for a specific asset

        Args:
            asset_id: The asset ID to fetch vulnerabilities for

        Returns:
            List of vulnerabilities
        """
        try:
            endpoint = f"{self.base_url}/GetVulnerabilities"
            payload = {"asset_id": asset_id}

            response = self.session.post(
                endpoint,
                json=payload,
                timeout=30
            )
            response.raise_for_status()

            vulnerabilities = response.json()
            return vulnerabilities if isinstance(vulnerabilities, list) else [vulnerabilities]

        except requests.exceptions.RequestException as e:
            print(f"Error fetching vulnerabilities for {asset_id}: {e}", file=sys.stderr)
            return []

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Fetch detailed scan results from FAZE

        Args:
            scan_id: The scan ID to fetch results for

        Returns:
            Scan results with vulnerabilities
        """
        try:
            endpoint = f"{self.base_url}/GetScanResults"
            payload = {"scan_id": scan_id}

            response = self.session.post(
                endpoint,
                json=payload,
                timeout=30
            )
            response.raise_for_status()

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"Error fetching scan results for {scan_id}: {e}", file=sys.stderr)
            return {}

    def parse_faze_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse FAZE API vulnerability response into Splunk event format

        Args:
            vuln: FAZE vulnerability object

        Returns:
            Splunk-formatted event
        """
        # Map FAZE severity to our severity levels
        faze_severity = vuln.get("severity", "medium").lower()
        severity_map = {
            "critical": SeverityLevel.CRITICAL.value,
            "high": SeverityLevel.HIGH.value,
            "medium": SeverityLevel.MEDIUM.value,
            "low": SeverityLevel.LOW.value,
            "info": SeverityLevel.INFO.value,
            "unknown": SeverityLevel.MEDIUM.value,
        }
        severity = severity_map.get(faze_severity, SeverityLevel.MEDIUM.value)

        # Calculate priority
        priority_map = {
            "critical": 100,
            "high": 80,
            "medium": 60,
            "low": 40,
            "info": 20,
        }
        priority = priority_map.get(severity, 50)

        # Parse CVE IDs
        cve_ids = []
        if "cve_id" in vuln:
            cve_id = vuln["cve_id"]
            if isinstance(cve_id, list):
                cve_ids = cve_id
            elif cve_id:
                cve_ids = [cve_id]

        if "cve_ids" in vuln:
            cve_ids.extend(vuln["cve_ids"] if isinstance(vuln["cve_ids"], list) else [vuln["cve_ids"]])

        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "vulnerability_detection",
            "source": "faze_security_api",
            "scan_timestamp": self.scan_timestamp.isoformat(),

            # Vulnerability details
            "vulnerability_id": vuln.get("id", "unknown"),
            "vulnerability_type": vuln.get("type", "unknown"),
            "severity": severity,
            "title": vuln.get("title", "Unknown Vulnerability"),
            "description": vuln.get("description", "No description provided"),
            "cve_ids": cve_ids,

            # Asset information
            "target": vuln.get("target", vuln.get("asset", "unknown")),
            "asset_id": vuln.get("asset_id", "unknown"),
            "asset_name": vuln.get("asset_name", "unknown"),
            "asset_type": vuln.get("asset_type", "unknown"),

            # Component information
            "affected_component": vuln.get("component", vuln.get("service", "Unknown")),
            "component_version": vuln.get("version", "unknown"),

            # CVSS and scoring
            "cvss_score": vuln.get("cvss_score", 0),
            "cvss_vector": vuln.get("cvss_vector", ""),
            "cvss_version": vuln.get("cvss_version", "3.1"),

            # Remediation
            "remediation": vuln.get("remediation", vuln.get("fix", "Manual review required")),
            "remediation_priority": priority,
            "fix_available": vuln.get("fix_available", False),

            # Additional details
            "discovered_date": vuln.get("discovered_date", ""),
            "last_seen": vuln.get("last_seen", ""),
            "status": vuln.get("status", "active"),

            # FAZE specific
            "faze_risk_score": vuln.get("risk_score", 0),
            "faze_exploitability": vuln.get("exploitability", "unknown"),
            "faze_proof_of_concept": vuln.get("proof_of_concept", ""),

            # References
            "references": vuln.get("references", []),
            "tags": vuln.get("tags", []),
        }

        return event

    def fetch_and_index_vulnerabilities(self) -> None:
        """Fetch all vulnerabilities from FAZE and prepare for Splunk indexing"""
        try:
            # Get all assets
            assets = self.get_assets()

            if not assets:
                print("# No assets found", file=sys.stderr)
                return

            print(f"# Found {len(assets)} assets", file=sys.stderr)

            # Process each asset
            for asset in assets:
                asset_id = asset.get("id") or asset.get("asset_id")
                if not asset_id:
                    continue

                print(f"# Fetching vulnerabilities for asset: {asset_id}", file=sys.stderr)

                # Get vulnerabilities for this asset
                vulnerabilities = self.get_vulnerabilities(asset_id)

                if not vulnerabilities:
                    print(f"# No vulnerabilities found for asset {asset_id}", file=sys.stderr)
                    continue

                print(f"# Found {len(vulnerabilities)} vulnerabilities for {asset_id}", file=sys.stderr)

                # Parse and store vulnerabilities
                for vuln in vulnerabilities:
                    event = self.parse_faze_vulnerability(vuln)
                    self.vulnerabilities.append(event)

        except Exception as e:
            print(f"Error during vulnerability scan: {e}", file=sys.stderr)

    def generate_splunk_events(self) -> List[str]:
        """Generate Splunk-formatted events"""
        splunk_events = []

        for vuln in self.vulnerabilities:
            timestamp = int(datetime.fromisoformat(vuln["timestamp"]).timestamp())
            json_data = json.dumps(vuln)
            event = f"{timestamp} {json_data}"
            splunk_events.append(event)

        return splunk_events

    def output_to_splunk(self) -> None:
        """Output events to Splunk"""
        events = self.generate_splunk_events()

        for event in events:
            print(event)

    def get_statistics(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        if not self.vulnerabilities:
            return {}

        severity_count = {}
        type_count = {}
        high_priority_count = 0

        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "unknown")
            vuln_type = vuln.get("vulnerability_type", "unknown")

            severity_count[severity] = severity_count.get(severity, 0) + 1
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1

            if vuln.get("remediation_priority", 0) >= 80:
                high_priority_count += 1

        # Calculate average CVSS
        cvss_scores = [v.get("cvss_score", 0) for v in self.vulnerabilities]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": severity_count,
            "by_type": type_count,
            "high_priority_count": high_priority_count,
            "average_cvss_score": round(avg_cvss, 2),
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "data_source": "FAZE Security API",
        }


def main():
    """Main entry point"""
    try:
        # Initialize addon
        addon = FAZESecurityAddon()

        # Fetch vulnerabilities from FAZE
        addon.fetch_and_index_vulnerabilities()

        # Output to Splunk
        addon.output_to_splunk()

        # Output statistics to stderr
        stats = addon.get_statistics()
        print(f"# Statistics: {json.dumps(stats)}", file=sys.stderr)

    except ValueError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        print("# Please set FAZE_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Fatal Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
