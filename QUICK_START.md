# Quick Start - Fetch FAZE Logs

Simple setup to fetch vulnerability logs from FAZE.

## Setup (2 minutes)

### 1. Install dependencies
```bash
pip install requests python-dotenv
```

### 2. Create .env file
```bash
cp .env.example .env
```

### 3. Add your FAZE API key to .env
```bash
nano .env
```

Edit and save:
```
FAZE_API_KEY=sk_live_your_api_key_here
```

## Usage

### Quick fetch
```bash
export $(cat .env | xargs) && python3 fetch_logs.py
```

Or without .env:
```bash
FAZE_API_KEY='sk_live_xxx' python3 fetch_logs.py
```

### Output
JSON vulnerability logs:
```json
{
  "timestamp": "2024-10-08T14:23:45.123456",
  "asset_id": "asset_123",
  "asset_name": "app.example.com",
  "vulnerability_id": "vuln_456",
  "type": "remote_code_execution",
  "severity": "critical",
  "title": "Unauthenticated RCE",
  "cvss_score": 9.8,
  "target": "10.0.1.5:80",
  "remediation": "Update to latest version"
}
```

## Send to Splunk

### Method 1: Direct stdin
```bash
FAZE_API_KEY='sk_live_xxx' python3 fetch_logs.py | splunk add oneshot -
```

### Method 2: Via HTTP Event Collector (HEC)
```bash
FAZE_API_KEY='sk_live_xxx' python3 fetch_logs.py | while read line; do
  curl -k https://splunk-server:8088/services/collector \
    -H "Authorization: Splunk $HEC_TOKEN" \
    -d "$line"
done
```

### Method 3: Save to file
```bash
FAZE_API_KEY='sk_live_xxx' python3 fetch_logs.py > vulnerabilities.json
```

That's it! You're fetching FAZE logs.

## Troubleshooting

**"Error: API key not provided"**
- Set environment variable: `export FAZE_API_KEY='your_key'`

**"No assets found"**
- Check FAZE dashboard for scanned assets
- Verify API key has permissions

**"Failed to fetch"**
- Check network connectivity
- Verify FAZE_API_URL is correct
- Check firewall/proxy settings
