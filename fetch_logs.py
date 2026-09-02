#!/usr/bin/env python3
"""
Simple FAZE Security API Log Fetcher
Fetches vulnerabilities and displays them as logs
"""

import os
import sys
import json
import requests
from datetime import datetime
from pathlib import Path

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


def fetch_logs(api_key: str, api_url: str = "https://api.faze.security", verify_ssl: bool = True) -> None:
    """Fetch and display logs from FAZE API"""

    if not api_key:
        print("Error: API key not provided")
        print("Usage: FAZE_API_KEY='your_key' python3 fetch_logs.py")
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
        # Fetch assets
        print("Fetching assets...", file=sys.stderr)
        response = session.post(f"{api_url}/GetAssets", json={})
        response.raise_for_status()
        assets = response.json()

        if not assets:
            print("No assets found", file=sys.stderr)
            return

        print(f"Found {len(assets)} assets", file=sys.stderr)

        # Fetch vulnerabilities for each asset
        for asset in assets:
            asset_id = asset.get("id") or asset.get("asset_id")
            asset_name = asset.get("name") or asset.get("asset_name", "Unknown")

            if not asset_id:
                continue

            print(f"Fetching vulnerabilities for: {asset_name}", file=sys.stderr)

            response = session.post(
                f"{api_url}/GetVulnerabilities",
                json={"asset_id": asset_id}
            )
            response.raise_for_status()
            vulns = response.json()

            if not vulns:
                continue

            # Output logs
            for vuln in vulns:
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    "vulnerability_id": vuln.get("id"),
                    "type": vuln.get("type"),
                    "severity": vuln.get("severity"),
                    "title": vuln.get("title"),
                    "description": vuln.get("description"),
                    "cve_id": vuln.get("cve_id"),
                    "cvss_score": vuln.get("cvss_score"),
                    "target": vuln.get("target"),
                    "remediation": vuln.get("remediation"),
                }
                print(json.dumps(log_entry))

        print(f"Done fetching logs", file=sys.stderr)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    api_key = os.getenv("FAZE_API_KEY")
    fetch_logs(api_key)
