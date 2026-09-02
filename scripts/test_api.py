#!/usr/bin/env python3
import os, json, requests, warnings
from dotenv import load_dotenv
from pathlib import Path

warnings.filterwarnings("ignore")

load_dotenv(Path('.env'))
api_key = os.getenv('FAZE_API_KEY')
api_url = 'https://api.faze.security'

session = requests.Session()
session.headers.update({'apikey': api_key, 'Content-Type': 'application/json'})
session.verify = False

response = session.post(f'{api_url}/GetAllAssets', json={'art_id': 1000}, timeout=30)
data = response.json()

print(f'Error Code: {data.get("Error")}')
print(f'Function: {data.get("Function")}')

if isinstance(data.get('Data'), str):
    assets = json.loads(data['Data'])
    print(f'Found {len(assets)} assets!')
    print('\nFirst 5 assets:')
    for i, asset in enumerate(assets[:5]):
        print(f'  {i+1}. {asset.get("asset")} (id: {asset.get("id")})')
    if len(assets) > 5:
        print(f'  ... and {len(assets)-5} more')
else:
    print(f'Data: {data.get("Data")}')
