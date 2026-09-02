#!/usr/bin/env python3
"""
Fetch all Agentic Red Team vulnerabilities by asset
Fetches vulnerabilities and associates them with assets
"""

import os
import sys
import json
import requests
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

warnings.filterwarnings("ignore")

try:
    from dotenv import load_dotenv
    # Look for .env in: config/.env or parent directories
    for env_path in [
        Path(__file__).parent.parent / "config" / ".env",
        Path(__file__).parent / ".env",
        Path(__file__).parent.parent / ".env",
    ]:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass


class AgenticRedTeamVulnFetcher:
    """Fetch all ART vulnerabilities by asset"""

    def __init__(self, api_key: str, api_url: str = "https://api.faze.security"):
        self.api_key = api_key
        self.api_url = api_url
        self.session = self._setup_session()
        self.vulns_count = 0

    def _setup_session(self) -> requests.Session:
        """Setup API session"""
        session = requests.Session()
        session.headers.update({
            "apikey": self.api_key,
            "Content-Type": "application/json"
        })
        session.verify = False
        return session

    def fetch_vulnerabilities(self, art_id: int, limit: int = 100) -> List[Dict]:
        """Fetch all vulnerabilities with pagination"""
        all_vulns = []
        offset = 0

        while True:
            try:
                response = self.session.post(
                    f"{self.api_url}/GetArtVulnerabilities",
                    json={
                        "art_id": art_id,
                        "limit": limit,
                        "offset": offset,
                    },
                    timeout=30
                )
                response.raise_for_status()
                data = response.json()

                if data.get("Error") != 0:
                    print(f"Error {data.get('Error')}: {data.get('Data')}", file=sys.stderr)
                    break

                vuln_data = data.get("Data", {})
                pagination = vuln_data.get("pagination", {})
                vulns = vuln_data.get("data", [])

                if not vulns:
                    break

                all_vulns.extend(vulns)

                # Check if there are more pages
                if not pagination.get("next", False):
                    break

                offset = pagination.get("next_offset", offset + limit)

            except Exception as e:
                print(f"Error fetching vulnerabilities: {e}", file=sys.stderr)
                break

        return all_vulns

    def fetch_assets(self, art_id: int) -> Dict[int, str]:
        """Fetch assets and map asset_id to asset_name"""
        try:
            response = self.session.post(
                f"{self.api_url}/GetAllAssets",
                json={"art_id": art_id},
                timeout=30
            )
            response.raise_for_status()
            response_data = response.json()

            if response_data.get("Error") != 0:
                print(f"Error fetching assets: {response_data.get('Data')}", file=sys.stderr)
                return {}

            data = response_data.get("Data")
            if isinstance(data, str):
                assets = json.loads(data)
            else:
                assets = data if isinstance(data, list) else []

            # Create mapping of asset_id to asset_name
            asset_map = {}
            for asset in assets:
                if isinstance(asset, dict):
                    asset_id = asset.get("id")
                    asset_name = asset.get("asset")
                    if asset_id and asset_name:
                        asset_map[asset_id] = asset_name

            return asset_map

        except Exception as e:
            print(f"Error fetching assets: {e}", file=sys.stderr)
            return {}

    def run(self, art_id: int = 1000):
        """Fetch and output all vulnerabilities"""
        print(f"Fetching ART vulnerabilities for art_id={art_id}...", file=sys.stderr)

        # Fetch assets
        print("Fetching assets...", file=sys.stderr)
        asset_map = self.fetch_assets(art_id)
        print(f"Found {len(asset_map)} assets", file=sys.stderr)

        # Fetch vulnerabilities
        print("Fetching vulnerabilities...", file=sys.stderr)
        vulns_grouped = self.fetch_vulnerabilities(art_id)
        print(f"Found {len(vulns_grouped)} vulnerability groups", file=sys.stderr)

        # Process and output vulnerabilities
        for vuln_group in vulns_grouped:
            # vuln_group is a dict with vuln_name as key
            for vuln_name, vuln_details in vuln_group.items():
                count = vuln_details.get("COUNT", 0)
                items = vuln_details.get("items", [])

                for item in items:
                    # Extract asset from action URL if present
                    action = item.get("action", "")
                    asset_id = None
                    asset_name = "Unknown"

                    # Try to match action to asset
                    if action:
                        for aid, aname in asset_map.items():
                            if aname in action or action.startswith(f"https://{aname}"):
                                asset_id = aid
                                asset_name = aname
                                break

                    vuln_entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "vulnerability",
                        "sourcetype": "faze:agentic_red_team",
                        "vulnerability_id": item.get("id"),
                        "vulnerability_name": vuln_name,
                        "severity": item.get("severity"),
                        "asset_id": asset_id,
                        "asset_name": asset_name,
                        "action": action,
                        "method": item.get("method"),
                        "key": item.get("key"),
                        "token": item.get("token"),
                        "fixed": item.get("fixed") == "1",
                        "last_date": item.get("last_date"),
                        "discovery_rank": item.get("rn"),
                    }
                    print(json.dumps(vuln_entry))
                    self.vulns_count += 1

        print(f"\nComplete! Fetched {self.vulns_count} total vulnerabilities", file=sys.stderr)


if __name__ == "__main__":
    api_key = os.getenv("FAZE_API_KEY")
    if not api_key:
        print("Error: FAZE_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    art_id = int(os.getenv("FAZE_ART_ID", "1000"))
    fetcher = AgenticRedTeamVulnFetcher(api_key)
    fetcher.run(art_id)
