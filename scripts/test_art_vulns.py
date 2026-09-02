#!/usr/bin/env python3
"""Test GetARTVulnerabilities endpoint"""

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

print("Testing GetARTVulnerabilities endpoint...")
print()

# Test 1: With art_id
print("1. With art_id=1000:")
response = session.post(f"{api_url}/GetARTVulnerabilities", json={"art_id": 1000}, timeout=10)
data = response.json()
print(f"   Error: {data.get('Error')}")
print(f"   Data: {str(data.get('Data'))[:100]}")

# Test 2: With art_id and asset_id
print("\n2. With art_id=1000 and asset_id=1000:")
response = session.post(f"{api_url}/GetARTVulnerabilities", json={"art_id": 1000, "asset_id": 1000}, timeout=10)
data = response.json()
print(f"   Error: {data.get('Error')}")
if isinstance(data.get('Data'), str):
    try:
        vulns = json.loads(data['Data'])
        print(f"   Found: {len(vulns)} vulnerabilities")
        if vulns:
            print(f"   First vuln: {json.dumps(vulns[0], indent=2)[:200]}")
    except:
        print(f"   Data: {str(data.get('Data'))[:100]}")
else:
    print(f"   Data: {str(data.get('Data'))[:100]}")

# Test 3: Just art_id to see structure
print("\n3. Full response with art_id=1000:")
response = session.post(f"{api_url}/GetARTVulnerabilities", json={"art_id": 1000}, timeout=10)
data = response.json()
print(json.dumps(data, indent=2)[:500])
