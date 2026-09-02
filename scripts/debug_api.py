#!/usr/bin/env python3
"""Debug API responses"""
import os
import sys
import json
import requests
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

api_key = os.getenv("FAZE_API_KEY")
api_url = os.getenv("FAZE_API_URL", "https://api.faze.security")
verify_ssl = not os.getenv("FAZE_DISABLE_SSL")

headers = {
    "apikey": api_key,
    "Content-Type": "application/json"
}

session = requests.Session()
session.headers.update(headers)
session.verify = verify_ssl

# Test GetAllAssets
print("Testing GetAllAssets...", file=sys.stderr)
response = session.post(f"{api_url}/GetAllAssets", json={}, timeout=30)
print("Status:", response.status_code, file=sys.stderr)
print("Response:", json.dumps(response.json(), indent=2))
