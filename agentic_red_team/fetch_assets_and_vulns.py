#!/usr/bin/env python3
"""
Fetch all assets and their vulnerabilities from FAZE API
Combines asset data with associated vulnerability data
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


def fetch_assets_and_vulnerabilities(api_key: str, api_url: str = "https://api.faze.security", verify_ssl: bool = True) -> None:
    """Fetch all assets and their vulnerabilities"""

    if not api_key:
        print("Error: API key not provided")
        print("Usage: FAZE_API_KEY='your_key' python3 fetch_assets_and_vulns.py")
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
        # Fetch all assets
        print("Fetching all assets...", file=sys.stderr)
        response = session.post(
            f"{api_url}/GetAllAssets",
            json={},
            timeout=30
        )
        response.raise_for_status()
        response_data = response.json()

        # Check for API errors
        if isinstance(response_data, dict):
            error_code = response_data.get("Error")
            if error_code and error_code != 0:
                print(f"API Error {error_code}: {response_data.get('Data', 'Unknown error')}", file=sys.stderr)
                sys.exit(1)

            # Parse nested API response format
            if "data" in response_data:
                api_data = response_data["data"]
                if isinstance(api_data, dict) and "Data" in api_data:
                    data_str = api_data["Data"]
                    try:
                        assets = json.loads(data_str) if isinstance(data_str, str) else data_str
                    except json.JSONDecodeError:
                        print(f"Failed to parse assets data: {data_str}", file=sys.stderr)
                        sys.exit(1)
                else:
                    assets = api_data if isinstance(api_data, list) else []
            elif "Data" in response_data:
                data_str = response_data["Data"]
                try:
                    assets = json.loads(data_str) if isinstance(data_str, str) else data_str
                except json.JSONDecodeError:
                    print(f"Failed to parse assets data: {data_str}", file=sys.stderr)
                    sys.exit(1)
            else:
                assets = []
        else:
            assets = response_data if isinstance(response_data, list) else [response_data]

        if not assets:
            print("No assets found", file=sys.stderr)
            return

        print(f"Found {len(assets)} assets", file=sys.stderr)

        # Fetch vulnerabilities for each asset
        total_vulns = 0
        for asset in assets:
            # Extract asset info
            if isinstance(asset, str):
                asset_id = asset
                asset_name = asset
                asset_tags = []
            elif isinstance(asset, dict):
                asset_id = asset.get("id")
                asset_name = asset.get("asset") or asset.get("name") or asset.get("asset_name", "Unknown")
                asset_tags = asset.get("tags", [])
            else:
                continue

            if not asset_id:
                continue

            # Format tags
            tag_names = [tag.get("tag_name", "") for tag in asset_tags if isinstance(tag, dict)]

            # Create asset entry
            asset_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sourcetype": "faze:asset",
                "asset_id": asset_id,
                "asset_name": asset_name,
                "tags": tag_names,
                "tag_count": len(asset_tags),
            }
            print(json.dumps(asset_entry))

            # Fetch vulnerabilities for this asset
            print(f"Fetching vulnerabilities for: {asset_name}", file=sys.stderr)
            try:
                vuln_response = session.post(
                    f"{api_url}/GetVulnerabilities",
                    json={"asset_id": asset_id},
                    timeout=30
                )
                vuln_response.raise_for_status()
                vulns = vuln_response.json()

                if not vulns:
                    continue

                # Handle response format
                if isinstance(vulns, dict):
                    vulns = [vulns]

                # Output vulnerability entries
                for vuln in vulns:
                    if isinstance(vuln, str):
                        vuln_id = vuln
                        vuln_type = None
                        severity = None
                        title = vuln
                        description = None
                        cve_id = None
                        cvss_score = None
                        remediation = None
                    elif isinstance(vuln, dict):
                        vuln_id = vuln.get("id") or vuln.get("vulnerability_id")
                        vuln_type = vuln.get("type")
                        severity = vuln.get("severity")
                        title = vuln.get("title")
                        description = vuln.get("description")
                        cve_id = vuln.get("cve_id")
                        cvss_score = vuln.get("cvss_score")
                        remediation = vuln.get("remediation")
                    else:
                        continue

                    vuln_entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "sourcetype": "faze:vulnerability",
                        "asset_id": asset_id,
                        "asset_name": asset_name,
                        "vulnerability_id": vuln_id,
                        "type": vuln_type,
                        "severity": severity,
                        "title": title,
                        "description": description,
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "remediation": remediation,
                    }
                    print(json.dumps(vuln_entry))
                    total_vulns += 1

            except requests.exceptions.RequestException as e:
                print(f"  Warning: Failed to fetch vulns for {asset_name}: {e}", file=sys.stderr)
                continue

        print(f"Done! Fetched {len(assets)} assets with {total_vulns} total vulnerabilities", file=sys.stderr)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    api_key = os.getenv("FAZE_API_KEY")
    fetch_assets_and_vulnerabilities(api_key)
