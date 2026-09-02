#!/usr/bin/env python3
import os, json, requests, warnings
from dotenv import load_dotenv
from pathlib import Path

warnings.filterwarnings("ignore")
load_dotenv(Path(".env"))

api_key = os.getenv("FAZE_API_KEY")
session = requests.Session()
session.headers.update({"apikey": api_key, "Content-Type": "application/json"})
session.verify = False

response = session.post("https://api.faze.security/GetArtVulnerabilities",
    json={"art_id": 1000, "limit": 10, "offset": 0}, timeout=10)
data = response.json()

print(f"Error: {data.get('Error')}")
print(f"Function: {data.get('Function')}")
if data.get("Data"):
    pagination = data["Data"].get("pagination", {})
    vulns = data["Data"].get("data", [])
    print(f"Total vulnerabilities: {pagination.get('total', 0)}")
    print(f"Found: {len(vulns)} entries")
    if vulns:
        print(f"\nFirst entry: {json.dumps(vulns[0], indent=2)[:300]}")
