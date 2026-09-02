#!/usr/bin/env python3
"""
Fetch agentic red team vulnerabilities
Retrieves the last 20 vulnerabilities from agentic red team scans
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


def fetch_agentic_red_team_vulnerabilities(api_key: str, limit: int = 20, api_url: str = "https://api.faze.security", verify_ssl: bool = True) -> None:
    """Fetch agentic red team vulnerabilities"""

    if not api_key:
        print("Error: API key not provided")
        print("Usage: FAZE_API_KEY='your_key' python3 fetch_agentic_red_team.py")
        sys.exit(1)

    # Check for SSL verification disable
    if os.getenv("DISABLE_SSL_VERIFY") or os.getenv("FAZE_DISABLE_SSL"):
        verify_ssl = False
        print("⚠️  WARNING: SSL verification disabled", file=sys.stderr)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    session = requests.Session()
    session.headers.update(headers)
    session.verify = verify_ssl

    try:
        # Fetch vulnerabilities with filter for agentic red team
        print(f"Fetching last {limit} agentic red team vulnerabilities...", file=sys.stderr)

        response = session.post(
            f"{api_url}/GetVulnerabilities",
            json={
                "source": "agentic_red_team",
                "limit": limit,
                "sort": "timestamp",
                "order": "desc"
            },
            timeout=30
        )
        response.raise_for_status()
        vulns = response.json()

        if not vulns:
            print("No vulnerabilities found", file=sys.stderr)
            return

        print(f"Found {len(vulns)} vulnerabilities", file=sys.stderr)

        # Output logs
        count = 0
        for vuln in vulns:
            if count >= limit:
                break

            # Handle different response formats (string vs dict)
            if isinstance(vuln, str):
                vulnerability_id = vuln
                vuln_type = None
                severity = None
                title = vuln
                description = None
                cve_id = None
                cvss_score = None
                target = None
                remediation = None
                source = "agentic_red_team"
            elif isinstance(vuln, dict):
                vulnerability_id = vuln.get("id") or vuln.get("vulnerability_id")
                vuln_type = vuln.get("type")
                severity = vuln.get("severity")
                title = vuln.get("title")
                description = vuln.get("description")
                cve_id = vuln.get("cve_id")
                cvss_score = vuln.get("cvss_score")
                target = vuln.get("target") or vuln.get("asset")
                remediation = vuln.get("remediation")
                source = vuln.get("source", "agentic_red_team")
            else:
                continue

            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "vulnerability_id": vulnerability_id,
                "source": source,
                "target": target,
                "type": vuln_type,
                "severity": severity,
                "title": title,
                "description": description,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "remediation": remediation,
            }
            print(json.dumps(log_entry))
            count += 1

        print(f"Done fetching {count} vulnerabilities", file=sys.stderr)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    api_key = os.getenv("FAZE_API_KEY")
    limit = int(os.getenv("FAZE_VULN_LIMIT", "20"))
    fetch_agentic_red_team_vulnerabilities(api_key, limit)
