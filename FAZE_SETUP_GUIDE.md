# FAZE Security API Integration Setup Guide

Complete guide for integrating FAZE Security API with the Splunk Add-on.

## Prerequisites

1. **FAZE Account**: Active account at https://app.faze.security
2. **API Key**: Generated from FAZE dashboard
3. **Python 3.6+**: For running the addon
4. **requests library**: `pip install requests python-dotenv`

## Step 1: Get Your FAZE API Key

1. Log in to FAZE Security: https://app.faze.security
2. Navigate to **Settings → API Keys**
3. Click **"Generate New API Key"**
4. Copy the generated key (you won't be able to see it again)
5. Store it securely (use .env file for local development only)

## Step 2: Set Up Local Environment

### Option A: Using .env File (Development)

**⚠️ IMPORTANT: Never commit .env to version control!**

1. Copy the example file:
```bash
cp .env.example .env
```

2. Edit `.env` and add your FAZE API key:
```bash
nano .env
```

3. Add your API key:
```env
FAZE_API_KEY=sk_live_abc123def456...
FAZE_API_URL=https://api.faze.security
```

4. Load environment variables when running Python:
```bash
export $(cat .env | xargs) && python3 bin/faze_security_addon.py
```

### Option B: Using System Environment Variables (Production)

```bash
export FAZE_API_KEY="sk_live_abc123def456..."
python3 bin/faze_security_addon.py
```

### Option C: Using Python Script with .env

Create `run_faze_addon.py`:

```python
#!/usr/bin/env python3
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

# Import and run addon
from bin.faze_security_addon import FAZESecurityAddon

if __name__ == "__main__":
    faze = FAZESecurityAddon()
    faze.fetch_and_index_vulnerabilities()
    faze.output_to_splunk()
```

Run with:
```bash
python3 run_faze_addon.py
```

## Step 3: Install Dependencies

```bash
pip install requests python-dotenv
```

Or from requirements file:
```bash
pip install -r requirements.txt
```

## Step 4: Test the Integration

### Quick Test

```bash
# Set API key
export FAZE_API_KEY="your_api_key_here"

# Run addon
python3 bin/faze_security_addon.py
```

Expected output:
```
1728374523 {"timestamp": "2024-10-08T...", "source": "faze_security_api", ...}
1728374524 {"timestamp": "2024-10-08T...", "source": "faze_security_api", ...}
# Statistics: {"total_vulnerabilities": 15, ...}
```

### Test with Sample Script

```bash
python3 test_faze_integration.py
```

See `test_faze_integration.py` for more detailed testing options.

## Step 5: Configure for Splunk

### Option A: Script Input (Recommended)

1. In Splunk, go to **Settings → Data Inputs → Scripts**
2. Click **"New"** and select the add-on
3. Configure:
   - **Script**: `faze_security_addon.py`
   - **Interval**: `3600` (hourly)
   - **Sourcetype**: `faze:vulnerability`
   - **Index**: `security`
4. Set environment variable in Splunk:
   - Create `/opt/splunk/etc/apps/agentic-red-team/local/.env`
   - Add: `FAZE_API_KEY=sk_live_...`

### Option B: Splunk Credential Store (Production)

Store API key securely in Splunk's credential store:

```bash
$SPLUNK_HOME/bin/splunk show-encrypted --value 'sk_live_...' -auth admin:password
```

Then reference in inputs.conf:
```conf
[faze_security://default]
python.version = python3
script = faze_security_addon.py
faze_api_key = $encrypted_credential_id
```

## API Endpoints

### GetAssets
Fetch all assets in your organization.

**Request:**
```python
POST /GetAssets
{
  "art_id": 1403  # Optional: filter by report ID
}
```

**Response:**
```json
[
  {
    "id": "asset_123",
    "name": "Production Web Server",
    "type": "web_server",
    "asset_name": "app.example.com"
  }
]
```

### GetVulnerabilities
Fetch vulnerabilities for a specific asset.

**Request:**
```python
POST /GetVulnerabilities
{
  "asset_id": "asset_123"
}
```

**Response:**
```json
[
  {
    "id": "vuln_456",
    "type": "remote_code_execution",
    "severity": "critical",
    "title": "Unauthenticated RCE in Apache",
    "cve_id": "CVE-2023-1234",
    "cvss_score": 9.8,
    "description": "...",
    "remediation": "Update to version 2.4.57",
    "target": "10.0.1.5:80"
  }
]
```

### GetScanResults
Fetch detailed results from a specific scan.

**Request:**
```python
POST /GetScanResults
{
  "scan_id": "scan_789"
}
```

## Field Mapping

How FAZE vulnerability data maps to Splunk fields:

| FAZE Field | Splunk Field | Description |
|-----------|--------------|-------------|
| id | vulnerability_id | Unique vulnerability ID |
| type | vulnerability_type | Type of vulnerability |
| severity | severity | Critical/High/Medium/Low/Info |
| title | title | Vulnerability title |
| cve_id | cve_ids | CVE identifiers |
| cvss_score | cvss_score | CVSS numeric score |
| target | target | Affected target (IP/hostname) |
| asset_id | asset_id | Asset ID from FAZE |
| remediation | remediation | Fix recommendation |
| status | status | Current status (active/fixed/etc) |
| discovered_date | discovered_date | When vulnerability was found |

## Example Splunk Queries

### All Critical Vulnerabilities from FAZE
```spl
source="faze_security_api" severity=critical
| table timestamp, target, title, cve_ids, remediation
```

### Vulnerabilities by Asset
```spl
source="faze_security_api"
| stats count by asset_id, severity
| sort - count
```

### High CVSS Score Vulnerabilities
```spl
source="faze_security_api" cvss_score > 7
| table target, title, cvss_score, remediation_priority
| sort - cvss_score
```

### Vulnerabilities with Available Fixes
```spl
source="faze_security_api" fix_available=true
| stats count by severity
```

## Troubleshooting

### "FAZE_API_KEY not provided"

**Problem**: Script can't find API key
**Solutions**:
1. Check .env file exists and is readable
2. Verify `export $(cat .env | xargs)` was run
3. Test with: `echo $FAZE_API_KEY`

### "401 Unauthorized"

**Problem**: Invalid or expired API key
**Solutions**:
1. Generate new key from FAZE dashboard
2. Verify key has correct format: `sk_live_...`
3. Check for whitespace in .env file

### "Connection refused"

**Problem**: Can't reach FAZE API
**Solutions**:
1. Verify FAZE_API_URL is correct
2. Check network/firewall rules
3. Test connectivity: `curl -I https://api.faze.security`

### "No vulnerabilities found"

**Problem**: Assets exist but no vulnerabilities returned
**Solutions**:
1. Verify assets have been scanned in FAZE
2. Check asset filters if using INCLUDE/EXCLUDE variables
3. Review asset status in FAZE dashboard

### "Request timeout"

**Problem**: FAZE API taking too long
**Solutions**:
1. Increase timeout in faze_security_addon.py (line 66: `timeout=30`)
2. Reduce number of assets being scanned
3. Try with specific asset_id parameter

## Best Practices

### Security
- ✅ Use .env file for local development only
- ✅ Use environment variables in production
- ✅ Use Splunk credential store for sensitive data
- ✅ Never commit API keys to version control
- ✅ Rotate API keys regularly
- ✅ Use firewall rules to restrict API access

### Performance
- ✅ Schedule scans during off-peak hours
- ✅ Use asset filtering to scan only critical systems
- ✅ Implement incremental scans instead of full scans
- ✅ Cache results when possible

### Monitoring
- ✅ Monitor FAZE API rate limits
- ✅ Log all API calls for audit trail
- ✅ Set up alerts for failed scans
- ✅ Track vulnerability trends over time

## Getting Help

- **FAZE Support**: support@faze.security
- **API Documentation**: https://docs.faze.security/api
- **Community Forum**: https://community.faze.security
- **GitHub Issues**: https://github.com/utopiabe/faze_splunk_logs/issues
