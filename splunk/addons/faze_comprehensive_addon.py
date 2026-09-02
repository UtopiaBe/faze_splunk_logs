#!/usr/bin/env python3
"""
FAZE Comprehensive Security API Integration for Splunk
Supports all API endpoints with audit logging and multiple sourcetypes
"""

import os
import sys
import json
import time
import logging
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from enum import Enum


class SourceType(Enum):
    """Different Splunk sourcetypes for FAZE data"""
    VULNERABILITIES = "faze:vulnerability"
    ASSETS = "faze:asset"
    COMPLIANCE = "faze:compliance"
    NETWORK = "faze:network"
    CREDENTIALS = "faze:credentials"
    MISCONFIGURATIONS = "faze:misconfiguration"
    AUDIT = "faze:audit"
    EXPLOITS = "faze:exploit"
    RISKS = "faze:risk"
    FINDINGS = "faze:finding"


class FAZEComprehensiveAddon:
    """Comprehensive FAZE API integration with all endpoints and audit logging"""

    def __init__(self, api_key: Optional[str] = None, enable_audit: bool = True):
        """Initialize addon with audit logging"""
        self.api_key = api_key or os.getenv("FAZE_API_KEY")
        if not self.api_key:
            raise ValueError("FAZE_API_KEY not provided")

        self.base_url = os.getenv("FAZE_API_URL", "https://api.faze.security")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Splunk-FAZE-Comprehensive/3.0"
        })

        # Setup logging
        self.enable_audit = enable_audit
        self.logger = self._setup_logging()
        self.events_by_sourcetype: Dict[str, List[Dict[str, Any]]] = {
            st.value: [] for st in SourceType
        }
        self.audit_log: List[Dict[str, Any]] = []

    def _setup_logging(self) -> logging.Logger:
        """Setup audit logging"""
        logger = logging.getLogger("FAZE_Addon")
        logger.setLevel(logging.INFO)

        if self.enable_audit:
            log_dir = Path(__file__).parent.parent / "logs"
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"

            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _audit_log(self, action: str, details: Dict[str, Any] = None) -> None:
        """Log audit event"""
        if not self.enable_audit:
            return

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": details or {},
            "source": "faze_addon"
        }
        self.audit_log.append(audit_entry)
        self.logger.info(f"AUDIT: {action} - {json.dumps(details or {})}")

    # ============ VULNERABILITY ENDPOINTS ============

    def get_vulnerabilities(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch vulnerabilities - GET /vulnerabilities"""
        self._audit_log("get_vulnerabilities", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetVulnerabilities",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            vulns = response.json()
            self._audit_log("get_vulnerabilities_success", {"count": len(vulns)})
            return vulns if isinstance(vulns, list) else [vulns]
        except Exception as e:
            self._audit_log("get_vulnerabilities_error", {"error": str(e)})
            return []

    def get_vulnerability_details(self, vuln_id: str) -> Dict[str, Any]:
        """Fetch vulnerability details - GET /vulnerabilities/{id}"""
        self._audit_log("get_vulnerability_details", {"vuln_id": vuln_id})
        try:
            response = self.session.post(
                f"{self.base_url}/GetVulnerabilityDetails",
                json={"vulnerability_id": vuln_id},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_vulnerability_details_error", {"vuln_id": vuln_id, "error": str(e)})
            return {}

    # ============ ASSET ENDPOINTS ============

    def get_assets(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch all assets - GET /assets"""
        self._audit_log("get_assets", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetAssets",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            assets = response.json()
            self._audit_log("get_assets_success", {"count": len(assets)})
            return assets if isinstance(assets, list) else [assets]
        except Exception as e:
            self._audit_log("get_assets_error", {"error": str(e)})
            return []

    def get_asset_details(self, asset_id: str) -> Dict[str, Any]:
        """Fetch asset details - GET /assets/{id}"""
        self._audit_log("get_asset_details", {"asset_id": asset_id})
        try:
            response = self.session.post(
                f"{self.base_url}/GetAssetDetails",
                json={"asset_id": asset_id},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_asset_details_error", {"asset_id": asset_id, "error": str(e)})
            return {}

    # ============ SCAN ENDPOINTS ============

    def get_scans(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch scans - GET /scans"""
        self._audit_log("get_scans", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetScans",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            scans = response.json()
            self._audit_log("get_scans_success", {"count": len(scans)})
            return scans if isinstance(scans, list) else [scans]
        except Exception as e:
            self._audit_log("get_scans_error", {"error": str(e)})
            return []

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Fetch scan results - GET /scans/{id}/results"""
        self._audit_log("get_scan_results", {"scan_id": scan_id})
        try:
            response = self.session.post(
                f"{self.base_url}/GetScanResults",
                json={"scan_id": scan_id},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_scan_results_error", {"scan_id": scan_id, "error": str(e)})
            return {}

    # ============ COMPLIANCE ENDPOINTS ============

    def get_compliance_findings(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch compliance findings - GET /compliance"""
        self._audit_log("get_compliance_findings", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetComplianceFindings",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            findings = response.json()
            self._audit_log("get_compliance_findings_success", {"count": len(findings)})
            return findings if isinstance(findings, list) else [findings]
        except Exception as e:
            self._audit_log("get_compliance_findings_error", {"error": str(e)})
            return []

    def get_compliance_status(self, framework: str = None) -> Dict[str, Any]:
        """Fetch compliance status - GET /compliance/status"""
        self._audit_log("get_compliance_status", {"framework": framework})
        try:
            response = self.session.post(
                f"{self.base_url}/GetComplianceStatus",
                json={"framework": framework} if framework else {},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_compliance_status_error", {"framework": framework, "error": str(e)})
            return {}

    # ============ NETWORK ENDPOINTS ============

    def get_network_findings(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch network findings - GET /network"""
        self._audit_log("get_network_findings", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetNetworkFindings",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            findings = response.json()
            self._audit_log("get_network_findings_success", {"count": len(findings)})
            return findings if isinstance(findings, list) else [findings]
        except Exception as e:
            self._audit_log("get_network_findings_error", {"error": str(e)})
            return []

    def get_open_ports(self, asset_id: str = None) -> List[Dict]:
        """Fetch open ports - GET /network/ports"""
        self._audit_log("get_open_ports", {"asset_id": asset_id})
        try:
            response = self.session.post(
                f"{self.base_url}/GetOpenPorts",
                json={"asset_id": asset_id} if asset_id else {},
                timeout=30
            )
            response.raise_for_status()
            ports = response.json()
            self._audit_log("get_open_ports_success", {"count": len(ports)})
            return ports if isinstance(ports, list) else [ports]
        except Exception as e:
            self._audit_log("get_open_ports_error", {"asset_id": asset_id, "error": str(e)})
            return []

    # ============ CREDENTIALS ENDPOINTS ============

    def get_exposed_credentials(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch exposed credentials - GET /credentials"""
        self._audit_log("get_exposed_credentials", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetExposedCredentials",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            creds = response.json()
            self._audit_log("get_exposed_credentials_success", {"count": len(creds)})
            return creds if isinstance(creds, list) else [creds]
        except Exception as e:
            self._audit_log("get_exposed_credentials_error", {"error": str(e)})
            return []

    # ============ MISCONFIGURATION ENDPOINTS ============

    def get_misconfigurations(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch misconfigurations - GET /misconfigurations"""
        self._audit_log("get_misconfigurations", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetMisconfigurations",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            misconfigs = response.json()
            self._audit_log("get_misconfigurations_success", {"count": len(misconfigs)})
            return misconfigs if isinstance(misconfigs, list) else [misconfigs]
        except Exception as e:
            self._audit_log("get_misconfigurations_error", {"error": str(e)})
            return []

    # ============ EXPLOIT ENDPOINTS ============

    def get_known_exploits(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Fetch known exploits - GET /exploits"""
        self._audit_log("get_known_exploits", {"filters": filters})
        try:
            response = self.session.post(
                f"{self.base_url}/GetKnownExploits",
                json=filters or {},
                timeout=30
            )
            response.raise_for_status()
            exploits = response.json()
            self._audit_log("get_known_exploits_success", {"count": len(exploits)})
            return exploits if isinstance(exploits, list) else [exploits]
        except Exception as e:
            self._audit_log("get_known_exploits_error", {"error": str(e)})
            return []

    # ============ RISK ENDPOINTS ============

    def get_risk_assessment(self) -> Dict[str, Any]:
        """Fetch risk assessment - GET /risk/assessment"""
        self._audit_log("get_risk_assessment")
        try:
            response = self.session.post(
                f"{self.base_url}/GetRiskAssessment",
                json={},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_risk_assessment_error", {"error": str(e)})
            return {}

    def get_risk_trends(self, days: int = 30) -> Dict[str, Any]:
        """Fetch risk trends - GET /risk/trends"""
        self._audit_log("get_risk_trends", {"days": days})
        try:
            response = self.session.post(
                f"{self.base_url}/GetRiskTrends",
                json={"days": days},
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self._audit_log("get_risk_trends_error", {"days": days, "error": str(e)})
            return {}

    # ============ FETCH ALL DATA ============

    def fetch_all_data(self) -> None:
        """Fetch all data from all endpoints"""
        self._audit_log("fetch_all_data_start")

        # Vulnerabilities
        vulns = self.get_vulnerabilities()
        for vuln in vulns:
            event = self._format_event(vuln, SourceType.VULNERABILITIES)
            self.events_by_sourcetype[SourceType.VULNERABILITIES.value].append(event)

        # Assets
        assets = self.get_assets()
        for asset in assets:
            event = self._format_event(asset, SourceType.ASSETS)
            self.events_by_sourcetype[SourceType.ASSETS.value].append(event)

        # Scans
        scans = self.get_scans()
        for scan in scans:
            event = self._format_event(scan, SourceType.ASSETS)
            self.events_by_sourcetype[SourceType.ASSETS.value].append(event)

        # Compliance
        compliance = self.get_compliance_findings()
        for finding in compliance:
            event = self._format_event(finding, SourceType.COMPLIANCE)
            self.events_by_sourcetype[SourceType.COMPLIANCE.value].append(event)

        # Network
        network = self.get_network_findings()
        for finding in network:
            event = self._format_event(finding, SourceType.NETWORK)
            self.events_by_sourcetype[SourceType.NETWORK.value].append(event)

        # Credentials
        creds = self.get_exposed_credentials()
        for cred in creds:
            event = self._format_event(cred, SourceType.CREDENTIALS)
            self.events_by_sourcetype[SourceType.CREDENTIALS.value].append(event)

        # Misconfigurations
        misconfigs = self.get_misconfigurations()
        for config in misconfigs:
            event = self._format_event(config, SourceType.MISCONFIGURATIONS)
            self.events_by_sourcetype[SourceType.MISCONFIGURATIONS.value].append(event)

        # Exploits
        exploits = self.get_known_exploits()
        for exploit in exploits:
            event = self._format_event(exploit, SourceType.EXPLOITS)
            self.events_by_sourcetype[SourceType.EXPLOITS.value].append(event)

        # Risk
        risk = self.get_risk_assessment()
        if risk:
            event = self._format_event(risk, SourceType.RISKS)
            self.events_by_sourcetype[SourceType.RISKS.value].append(event)

        self._audit_log("fetch_all_data_complete", {
            "total_events": sum(len(v) for v in self.events_by_sourcetype.values())
        })

    def _format_event(self, data: Dict[str, Any], sourcetype: SourceType) -> Dict[str, Any]:
        """Format event for Splunk"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "sourcetype": sourcetype.value,
            "source": "faze_api",
            **data
        }

    def output_all_events(self) -> None:
        """Output all events to stdout"""
        for sourcetype, events in self.events_by_sourcetype.items():
            for event in events:
                timestamp = int(datetime.fromisoformat(event["timestamp"]).timestamp())
                print(f"{timestamp} {json.dumps(event)}")

    def output_audit_log(self) -> None:
        """Output audit log"""
        for entry in self.audit_log:
            timestamp = int(datetime.fromisoformat(entry["timestamp"]).timestamp())
            event = {
                "sourcetype": SourceType.AUDIT.value,
                "source": "faze_addon",
                **entry
            }
            print(f"{timestamp} {json.dumps(event)}")


def main():
    """Main entry point"""
    try:
        addon = FAZEComprehensiveAddon()
        addon.fetch_all_data()
        addon.output_all_events()
        addon.output_audit_log()
    except ValueError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Fatal Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
