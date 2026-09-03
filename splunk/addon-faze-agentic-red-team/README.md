# FAZE Agentic Red Team Add-on for Splunk

Splunk Add-on for fetching vulnerability data from FAZE Security's Agentic Red Team (ART) API.

**Compatible with:** Splunk 9.4.7 and later

## Features

✅ **Complete Vulnerability Ingestion** — Fetches all ART vulnerabilities with asset mapping  
✅ **Automatic Deduplication** — Optional dedup to show first occurrence per asset  
✅ **CIM Compliant** — Field mappings for Common Information Model  
✅ **Configurable Scheduling** — Default 6-hour interval (customizable)  
✅ **Error Handling** — Built-in error logging and restart on failure  
✅ **Splunk Cloud Ready** — Works on Splunk Cloud and on-premises  

## Installation

### 1. Extract the Add-on
```bash
# Copy addon to Splunk apps directory
cp -r addon-faze-agentic-red-team $SPLUNK_HOME/etc/apps/
```

Or for Splunk Cloud:
```bash
# Use Splunk Cloud app management UI or
cp -r addon-faze-agentic-red-team $SPLUNK_HOME/etc/deployment-apps/
```

### 2. Set API Credentials

**Option A: Environment Variables**
```bash
export FAZE_API_KEY="your-api-key-here"
export FAZE_ART_ID="1000"
export FAZE_DEDUP_VULNS="true"
```

**Option B: .env File**
```bash
# Create config/.env in project root
FAZE_API_KEY=your-api-key-here
FAZE_ART_ID=1000
FAZE_DEDUP_VULNS=true
```

**Option C: Splunk UI (Recommended)**
1. Navigate to: **Settings → Data Inputs → FAZE Agentic Red Team**
2. Click **Create New Input**
3. Enter your API credentials
4. Click **Save**

### 3. Restart Splunk
```bash
$SPLUNK_HOME/bin/splunk restart
```

## Configuration

### Input Settings (`inputs.conf`)

| Setting | Default | Description |
|---------|---------|-------------|
| `interval` | 21600 | Fetch interval in seconds (6 hours) |
| `index` | security | Splunk index for events |
| `sourcetype` | faze:agentic_red_team | Event sourcetype |
| `disabled` | false | Enable/disable input |

### Environment Variables

| Variable | Required | Default | Example |
|----------|----------|---------|---------|
| `FAZE_API_KEY` | Yes | - | `vJySWYkE-6WQ3...` |
| `FAZE_ART_ID` | No | 1000 | `1000` |
| `FAZE_DEDUP_VULNS` | No | false | `true` or `false` |

### Deduplication

**When disabled (default):**
- Indexes all 1,069 vulnerabilities
- Includes duplicate findings on same asset
- Useful for: Trend analysis, historical tracking

**When enabled (`FAZE_DEDUP_VULNS=true`):**
- Indexes 667 unique vulnerabilities
- Shows first occurrence per asset only
- Removes 402 duplicates (37% reduction)
- Useful for: Security review, actionable findings

## Data Indexed

### Sourcetype: `faze:agentic_red_team`

Each event includes:

```json
{
  "timestamp": "2026-09-02T11:34:34.477028+00:00",
  "event_type": "vulnerability",
  "sourcetype": "faze:agentic_red_team",
  "vulnerability_id": 15634,
  "vulnerability_name": "Internal Service Context...",
  "severity": "High",
  "asset_id": 1082,
  "asset_name": "developer-nonprod.discountbank.co.il",
  "action": "https://developer-nonprod.discountbank.co.il/...",
  "method": "POST",
  "key": "activation_token",
  "token": "jb4cx1w3-g927-spn6-b041owno",
  "fixed": false,
  "last_date": "16-08-2026 | 11:43:53",
  "discovery_rank": 1,
  "priority": 2,
  "risk_score": 80,
  "category": "Vulnerability Detection",
  "vendor": "FAZE Security",
  "product": "Agentic Red Team"
}
```

### Field Mappings

| Field | Description | Type |
|-------|-------------|------|
| `vulnerability_id` | Unique vulnerability identifier | Number |
| `vulnerability_name` | Title of vulnerability | String |
| `severity` | Critical/High/Medium/Low/Informative | String |
| `asset_id` | Associated asset ID | Number |
| `asset_name` | Associated asset domain/name | String |
| `action` | Vulnerable endpoint URL | String |
| `method` | HTTP method (GET/POST/etc) | String |
| `fixed` | Whether vulnerability is patched | Boolean |
| `priority` | Severity-based priority (1=highest) | Number |
| `risk_score` | Risk score 0-100 | Number |
| `category` | CIM category | String |

## Searching Data

### All Vulnerabilities
```spl
sourcetype="faze:agentic_red_team"
```

### Critical Vulnerabilities Only
```spl
sourcetype="faze:agentic_red_team" severity="Critical" OR severity="High"
```

### By Asset
```spl
sourcetype="faze:agentic_red_team" 
| stats count by asset_name
```

### By Severity
```spl
sourcetype="faze:agentic_red_team" 
| stats count by severity
```

### High-Risk Assets
```spl
sourcetype="faze:agentic_red_team" severity="High" OR severity="Critical"
| stats count, sum(risk_score) as total_risk by asset_name
| sort - total_risk
```

## Troubleshooting

### No Data Appears

1. **Check if input is enabled:**
   ```spl
   | rest /services/data/inputs/faze_agentic_red_team
   | fields title, disabled
   ```

2. **Check input logs:**
   ```spl
   index=_internal source="*faze*" group="thruput"
   ```

3. **Verify API credentials:**
   ```bash
   export FAZE_API_KEY="your-key"
   python bin/fetch_agentic_red_team.py
   ```

### API Connection Errors

- Verify API key is correct: `echo $FAZE_API_KEY`
- Check network connectivity: `curl https://api.faze.security`
- Verify API URL in script: `grep "api_url" bin/fetch_agentic_red_team.py`

### Splunk Cloud Deployment

1. Upload addon via **Manage Apps** → **Install app from file**
2. Set environment variables in **Settings → General Settings → Environment Variables**
3. Restart Splunk

## Performance Notes

- **Fetch time**: ~30-60 seconds for all vulnerabilities
- **Memory**: ~50-100MB for complete dataset
- **Requests**: ~11 paginated API calls (limit=100 per request)
- **Recommended interval**: 6-12 hours (default: 6 hours)

## Log Locations

```
$SPLUNK_HOME/var/log/splunk/splunkd.log         # Main log
$SPLUNK_HOME/var/log/splunk/metrics.log         # Performance metrics
<index>_internal (sourcetype=splunkd)           # Splunk internal logs
```

Search for addon logs:
```spl
index=_internal source="*fetch_agentic_red_team*"
```

## Splunk Cloud Specific

For Splunk Cloud deployments:
1. Use **Deployment Apps** instead of **Apps**
2. Set environment variables through **Settings → General Settings**
3. SSL/TLS is automatically handled
4. HTTP proxy settings available in **Settings → HTTP Event Collector**

## Support

For issues or questions:
1. Check logs: `index=_internal source="*faze*"`
2. Review configuration: `inputs.conf`, `props.conf`
3. Test manually: `python bin/fetch_agentic_red_team.py`
4. Verify API connectivity and credentials

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-09-02 | Initial release |

## License

Proprietary - FAZE Security

## Credits

Built for integration with FAZE Security Agentic Red Team Platform
