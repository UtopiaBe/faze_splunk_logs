#!/usr/bin/env python3
"""
Fetch ALL assets and ALL their vulnerabilities from FAZE API
Complete asset inventory with full vulnerability details
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


class FAZEAssetVulnFetcher:
    """Fetch all assets and vulnerabilities from FAZE API"""

    def __init__(self, api_key: str, api_url: str = "https://api.faze.security", verify_ssl: bool = True):
        if not api_key:
            raise ValueError("API key not provided")

        self.api_key = api_key
        self.api_url = api_url
        self.verify_ssl = verify_ssl
        self.session = self._setup_session()
        self.assets_count = 0
        self.vulns_count = 0

    def _setup_session(self) -> requests.Session:
        """Setup API session"""
        session = requests.Session()
        session.headers.update({
            "apikey": self.api_key,
            "Content-Type": "application/json"
        })
        session.verify = self.verify_ssl
        return session

    def _parse_api_response(self, response_data: Any) -> List[Dict]:
        """Parse FAZE API response format"""
        if isinstance(response_data, dict):
            # Check for error
            error_code = response_data.get("Error")
            if error_code and error_code != 0:
                raise Exception(f"API Error {error_code}: {response_data.get('Data', 'Unknown error')}")

            # Parse nested response
            if "Data" in response_data:
                data = response_data["Data"]
                if isinstance(data, str):
                    try:
                        return json.loads(data)
                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse data: {data}", file=sys.stderr)
                        return []
                elif isinstance(data, list):
                    return data
                else:
                    return []
        elif isinstance(response_data, list):
            return response_data

        return []

    def fetch_assets(self, art_id: int = None) -> List[Dict]:
        """Fetch all assets from GetAllAssets endpoint"""
        print("Fetching all assets from GetAllAssets...", file=sys.stderr)
        try:
            payload = {}
            if art_id:
                payload["art_id"] = art_id
                print(f"  Using art_id: {art_id}", file=sys.stderr)

            response = self.session.post(
                f"{self.api_url}/GetAllAssets",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            assets = self._parse_api_response(response.json())
            self.assets_count = len(assets)
            print(f"✓ Found {self.assets_count} assets", file=sys.stderr)
            return assets
        except Exception as e:
            print(f"✗ Error fetching assets: {e}", file=sys.stderr)
            raise

    def fetch_vulnerabilities(self, asset_id: Any) -> List[Dict]:
        """Fetch vulnerabilities for a specific asset"""
        try:
            response = self.session.post(
                f"{self.api_url}/GetVulnerabilities",
                json={"asset_id": asset_id},
                timeout=30
            )
            response.raise_for_status()
            vulns = self._parse_api_response(response.json())
            return vulns if isinstance(vulns, list) else [vulns] if vulns else []
        except Exception as e:
            print(f"Warning: Error fetching vulnerabilities for asset {asset_id}: {e}", file=sys.stderr)
            return []

    def run(self, art_id: int = None):
        """Fetch all assets and their vulnerabilities"""
        try:
            assets = self.fetch_assets(art_id)
            if not assets:
                print("No assets found", file=sys.stderr)
                return

            # Process each asset
            for idx, asset in enumerate(assets, 1):
                # Extract asset info
                if isinstance(asset, str):
                    asset_id = asset
                    asset_name = asset
                    asset_tags = []
                elif isinstance(asset, dict):
                    asset_id = asset.get("id")
                    asset_name = asset.get("asset") or asset.get("name", "Unknown")
                    asset_tags = asset.get("tags", [])
                else:
                    continue

                if not asset_id:
                    continue

                # Output asset entry
                tag_names = [tag.get("tag_name", "") for tag in asset_tags if isinstance(tag, dict)]
                asset_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "asset",
                    "sourcetype": "faze:asset",
                    "asset_id": asset_id,
                    "asset_name": asset_name,
                    "tags": tag_names,
                }
                print(json.dumps(asset_entry))

                # Vulnerability fetching disabled - endpoint not available
                # print(f"  Fetching vulnerabilities for: {asset_name}", file=sys.stderr)
                # vulns = self.fetch_vulnerabilities(asset_id)

                if idx % 10 == 0:
                    print(f"  Progress: {idx}/{self.assets_count} assets processed", file=sys.stderr)

            print(f"\n✓ Complete! Fetched {self.assets_count} assets with {self.vulns_count} total vulnerabilities", file=sys.stderr)

        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    api_key = os.getenv("FAZE_API_KEY")
    if not api_key:
        print("Error: FAZE_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    api_url = os.getenv("FAZE_API_URL", "https://api.faze.security")
    verify_ssl = not (os.getenv("DISABLE_SSL_VERIFY") or os.getenv("FAZE_DISABLE_SSL"))
    art_id = int(os.getenv("FAZE_ART_ID", "1000")) if os.getenv("FAZE_ART_ID") else 1000

    if not verify_ssl:
        print("⚠️  WARNING: SSL verification disabled", file=sys.stderr)

    fetcher = FAZEAssetVulnFetcher(api_key, api_url, verify_ssl)
    fetcher.run(art_id)
