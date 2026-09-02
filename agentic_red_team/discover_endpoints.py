#!/usr/bin/env python3
"""Discover available API endpoints for vulnerabilities"""

import os
import json
import requests
import warnings
from pathlib import Path
from dotenv import load_dotenv

warnings.filterwarnings("ignore")

load_dotenv(Path('.env'))
api_key = os.getenv('FAZE_API_KEY')
api_url = os.getenv('FAZE_API_URL', 'https://api.faze.security')

session = requests.Session()
session.headers.update({'apikey': api_key, 'Content-Type': 'application/json'})
session.verify = False

# Try different endpoint variations
endpoints = [
    'GetVulnerabilities',
    'GetRedTeamVulnerabilities',
    'GetAgenticRedTeamVulnerabilities',
    'GetFindings',
    'GetVulnerabilitiesByAsset',
    'GetAssetVulnerabilities',
    'GetRedTeamFindings',
    'GetAssessmentVulnerabilities',
]

print("Testing endpoints for vulnerabilities:\n")

for endpoint in endpoints:
    try:
        # Try with just art_id
        response = session.post(
            f"{api_url}/{endpoint}",
            json={"art_id": 1000},
            timeout=10
        )
        data = response.json()
        error_code = data.get('Error')
        error_msg = data.get('Data', 'Unknown')

        if error_code == 0:
            print(f"✓ {endpoint}: SUCCESS")
        elif error_code == 1:
            print(f"⚠ {endpoint}: Missing parameters - {error_msg}")
        else:
            print(f"✗ {endpoint}: Error {error_code} - {error_msg}")
    except Exception as e:
        print(f"✗ {endpoint}: {str(e)[:50]}")

print("\n" + "="*60)
print("If you know the correct endpoint name, please provide it!")
