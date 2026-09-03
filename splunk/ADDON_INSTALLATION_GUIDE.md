# FAZE Agentic Red Team Splunk Add-on Installation Guide

Professional Splunk add-on for FAZE Agentic Red Team (ART) vulnerability ingestion.

## Quick Start

### 1. Install Add-on

**For Splunk Enterprise:**
```bash
# Copy addon to apps directory
cp -r addon-faze-agentic-red-team $SPLUNK_HOME/etc/apps/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

**For Splunk Cloud:**
```bash
# Upload via Manage Apps UI or use API
# Place in deployment-apps for deployment server
cp -r addon-faze-agentic-red-team $SPLUNK_HOME/etc/deployment-apps/
```

### 2. Configure API Credentials

**Via Splunk UI (Recommended):**
1. Go to **Settings → Data Inputs**
2. Click **FAZE Agentic Red Team**
3. Click **Create New Input** / **Edit**
4. Enter API Key: `your-api-key-here`
5. Leave ART ID as `1000` (default)
6. Enable deduplication if desired
7. Click **Save**

**Via Environment Variables:**
```bash
export FAZE_API_KEY="your-api-key-here"
export FAZE_ART_ID="1000"
export FAZE_DEDUP_VULNS="false"
```

**Via .env File:**
Create `config/.env`:
```
FAZE_API_KEY=your-api-key-here
FAZE_ART_ID=1000
FAZE_DEDUP_VULNS=false
```

### 3. Verify Installation

```spl
# Search for indexed data
sourcetype="faze:agentic_red_team"

# Check input status
| rest /services/data/inputs/faze_agentic_red_team

# View logs
index=_internal source="*faze*"
```

## Add-on Structure

```
addon-faze-agentic-red-team/
├── bin/
│   └── fetch_agentic_red_team.py      # Main input script
├── default/
│   ├── app.conf                        # App manifest
│   ├── inputs.conf                     # Input configuration
│   ├── props.conf                      # Field extraction
│   ├── setup.xml                       # UI configuration
│   └── transforms.conf                 # (optional) Transforms
├── metadata/
│   └── default.meta                    # Metadata configuration
├── README.md                           # Full documentation
└── MANIFEST.in                         # Package manifest
```

## Configuration Details

### inputs.conf

Key settings:

```ini
[faze_agentic_red_team://FAZE_ART]
# Scheduling (default: every 6 hours)
interval = 21600                    # seconds

# Splunk settings
index = security                    # Target index
sourcetype = faze:agentic_red_team  # Event sourcetype

# Execution
script = fetch_agentic_red_team.py
python.version = python3
disabled = false                    # Enable/disable
```

**Common Modifications:**

```ini
# Fetch every 2 hours instead of 6
interval = 7200

# Use different index
index = my_vulnerabilities

# Run in a different host context
host = faze-collector
```

### props.conf

Field extraction configuration:

```
[faze:agentic_red_team]
SHOULD_LINEMERGE = false
KV_MODE = json
INDEXED_EXTRACTIONS = json

# Auto-calculated fields:
# - priority (1-5 based on severity)
# - risk_score (0-100 based on severity)
# - category (Vulnerability Detection)
```

### setup.xml

UI configuration for Settings → Data Inputs

Provides user-friendly interface for:
- API Key configuration
- ART ID
- Deduplication toggle
- Index and interval settings
- Log level and timeout options

## Environment Variables

Required:
- `FAZE_API_KEY` — API authentication key

Optional:
- `FAZE_ART_ID` — ART ID (default: 1000)
- `FAZE_DEDUP_VULNS` — Deduplication (true/false, default: false)

### Priority Levels

| Severity | Priority | Risk Score |
|----------|----------|------------|
| Critical | 1 | 100 |
| High | 2 | 80 |
| Medium | 3 | 60 |
| Low | 4 | 40 |
| Informative | 5 | 20 |

## Data Model (CIM Compliant)

The add-on indexes data as CIM-compatible vulnerability events:

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | Event time | 2026-09-02T11:34:34.477028+00:00 |
| `sourcetype` | Splunk sourcetype | faze:agentic_red_team |
| `source` | Data source | faze:agentic_red_team |
| `host` | Event host | asset_name or FAZE_ART |
| `vulnerability_id` | Vuln ID | 15634 |
| `vulnerability_name` | Vuln title | "Internal Service Context..." |
| `severity` | Severity level | High |
| `asset_id` | Asset ID | 1082 |
| `asset_name` | Asset name | developer-nonprod.discountbank.co.il |
| `action` | Vulnerable endpoint | https://... |
| `method` | HTTP method | POST |
| `priority` | Severity rank (1-5) | 2 |
| `risk_score` | Risk 0-100 | 80 |

## Splunk Cloud Deployment

### Step 1: Upload Add-on

**Option A: Via UI**
1. **Manage Apps** → **Install app from file**
2. Select `addon-faze-agentic-red-team` folder (as .tar.gz)
3. Click **Upload**

**Option B: Via Deployment Server**
1. Place addon in deployment-apps
2. Update `serverclass.conf` on deployment server

### Step 2: Set Environment Variables

1. **Settings** → **General Settings** → **Environment Variables**
2. Add:
   ```
   FAZE_API_KEY=your-api-key-here
   FAZE_ART_ID=1000
   FAZE_DEDUP_VULNS=false
   ```

### Step 3: Verify

```spl
sourcetype="faze:agentic_red_team" | head 10
```

## Performance Tuning

### Fetch Interval Recommendations

| Use Case | Interval | Notes |
|----------|----------|-------|
| Development/Testing | 3600 (1 hr) | Frequent updates |
| Standard | 21600 (6 hrs) | Default, balanced |
| Production | 43200 (12 hrs) | Less frequent |
| Minimal Load | 86400 (24 hrs) | Daily checks |

### Deduplication Impact

**Without dedup (default):**
- Events indexed: 1,069
- Storage: ~550KB
- Processing: Normal

**With dedup enabled:**
- Events indexed: 667
- Storage: ~360KB
- Processing: Normal (dedup in-script)
- Reduction: 38% fewer events

### Resource Usage

- **CPU**: ~5% during fetch
- **Memory**: ~50-100MB
- **Network**: ~2-3MB per fetch
- **Storage**: ~550KB per run

## Search Queries

### All Vulnerabilities
```spl
sourcetype="faze:agentic_red_team"
```

### By Severity
```spl
sourcetype="faze:agentic_red_team" severity="High" OR severity="Critical"
| stats count by severity
```

### By Asset
```spl
sourcetype="faze:agentic_red_team"
| stats count by asset_name
| sort - count
```

### Asset Risk Score
```spl
sourcetype="faze:agentic_red_team"
| stats sum(risk_score) as total_risk by asset_name
| eval risk_level = case(
    total_risk >= 500, "CRITICAL",
    total_risk >= 300, "HIGH",
    total_risk >= 100, "MEDIUM",
    1=1, "LOW"
  )
| sort - total_risk
```

### Unfixed Vulnerabilities
```spl
sourcetype="faze:agentic_red_team" fixed="false"
| stats count as unresolved by severity
```

## Troubleshooting

### No Data Indexed

```spl
# Check if input is running
| rest /services/data/inputs/faze_agentic_red_team | fields title, disabled, state

# View input logs
index=_internal source="*fetch_agentic_red_team*"

# Check for errors
index=_internal ERROR source="*faze*"
```

### Slow Fetch Times

- Check network connectivity: `curl https://api.faze.security`
- Verify API key validity
- Check for rate limiting in logs
- Increase timeout if needed (default: 30s)

### API Authentication Errors

1. Verify API key: `echo $FAZE_API_KEY`
2. Check key hasn't expired
3. Verify ART ID is correct
4. Test manually:
   ```bash
   export FAZE_API_KEY="your-key"
   python bin/fetch_agentic_red_team.py
   ```

## Monitoring & Alerting

### Monitor Fetch Success

```spl
index=_internal source="*faze*" "Complete! Fetched"
| stats latest(eval(round(random()*100))) as fetch_success
```

### Alert on Failures

```spl
index=_internal source="*faze*" (ERROR OR "connection")
| alert
```

### Track Data Volume

```spl
sourcetype="faze:agentic_red_team"
| stats count by date_mday
| timechart avg(count)
```

## Support & Documentation

See `README.md` in addon folder for:
- Complete feature list
- CIM mappings
- Splunk Cloud specifics
- Performance notes

## Version Info

- **Add-on Version**: 1.0.0
- **Splunk Compatibility**: 9.4.7+
- **Python**: 3.7+
- **Release Date**: 2026-09-02
