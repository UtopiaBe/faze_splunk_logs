# Usage Guide - Organized Project Structure

## Setup

1. **Copy .env to config directory:**
   ```bash
   cp config/.env.example config/.env
   # Edit with your API key
   ```

2. **Set environment:**
   ```bash
   export FAZE_API_KEY="your-api-key-here"
   export FAZE_ART_ID="1000"
   export FAZE_DEDUP_VULNS="true"  # optional
   ```

## Usage Patterns

### Pattern 1: From Project Root

```bash
# Fetch all vulnerabilities
python agentic_red_team/fetch_agentic_red_team_vulns.py

# With deduplication
export FAZE_DEDUP_VULNS="true"
python agentic_red_team/fetch_agentic_red_team_vulns.py > output/vulns_dedup.jsonl

# Send to Splunk
python splunk/addons/faze_security_addon.py | \
  curl -X POST https://splunk-hec:8088/services/collector \
  -H "Authorization: Splunk <token>" -d @-
```

### Pattern 2: From Subdirectory

```bash
# Navigate to agentic_red_team
cd agentic_red_team
python fetch_agentic_red_team_vulns.py

# Navigate to splunk addons
cd splunk/addons
python faze_security_addon.py
```

### Pattern 3: One-off Commands

```bash
# Quick test
python agentic_red_team/discover_endpoints.py

# Debug API
python scripts/test_getart.py

# Generate test data
python splunk/addons/agentic_red_team_input.py --count 50
```

## Output Destinations

```bash
# Save to file
python agentic_red_team/fetch_agentic_red_team_vulns.py > output/my_vulns.jsonl

# Pipe to Splunk HEC
python splunk/addons/faze_security_addon.py | splunk add oneshot stdin://

# Pipe to processing
python agentic_red_team/fetch_agentic_red_team_vulns.py | jq '.severity' | sort | uniq -c

# Chain with dedup and filtering
python splunk/addons/faze_security_addon.py | \
  jq 'select(.severity == "High")' > output/high_severity.jsonl
```

## Configuration Options

### Environment Variables

| Variable | Default | Options | Example |
|----------|---------|---------|---------|
| `FAZE_API_KEY` | - | Any valid key | `your-api-key-here` |
| `FAZE_API_URL` | `https://api.faze.security` | Any URL | `https://api.faze.security` |
| `FAZE_ART_ID` | `1000` | Numeric ID | `1000` |
| `FAZE_DEDUP_VULNS` | `false` | `true` or `false` | `true` |

### Deduplication Behavior

**Without dedup (`FAZE_DEDUP_VULNS=false` or not set):**
- Returns all 1,069 vulnerabilities
- Some vulnerabilities appear multiple times across assets
- Useful for: Complete inventory, historical tracking

**With dedup (`FAZE_DEDUP_VULNS=true`):**
- Returns 667 unique vulnerabilities (first occurrence per asset)
- Removes 402 duplicate entries (37% reduction)
- Useful for: Security review, dashboards, actionable findings

## Common Workflows

### Workflow 1: Full Scan with Dedup

```bash
#!/bin/bash
export FAZE_API_KEY="your-api-key"
export FAZE_ART_ID="1000"
export FAZE_DEDUP_VULNS="true"

echo "📊 Running FAZE security scan..."
python splunk/addons/faze_security_addon.py > output/scan_$(date +%Y%m%d_%H%M%S).jsonl

echo "✅ Scan complete"
echo "📈 Statistics:"
cat output/scan_*.jsonl | jq -s 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Workflow 2: High-Severity Only

```bash
#!/bin/bash
export FAZE_API_KEY="your-api-key"
export FAZE_DEDUP_VULNS="true"

python splunk/addons/faze_security_addon.py | \
  jq 'select(.severity == "High" or .severity == "Critical")' \
  > output/critical_vulns.jsonl

echo "Found $(wc -l < output/critical_vulns.jsonl) critical/high vulns"
```

### Workflow 3: Asset-Specific Report

```bash
#!/bin/bash
export FAZE_API_KEY="your-api-key"

python agentic_red_team/fetch_agentic_red_team_vulns.py | \
  jq -s 'group_by(.asset_name) | 
         map({
           asset: .[0].asset_name,
           total: length,
           high: [.[] | select(.severity=="High")] | length,
           medium: [.[] | select(.severity=="Medium")] | length
         }) | 
         sort_by(.high) | 
         reverse' | jq .
```

### Workflow 4: Splunk Integration

```bash
#!/bin/bash
export FAZE_API_KEY="your-api-key"
export FAZE_DEDUP_VULNS="true"
SPLUNK_HEC_URL="https://splunk.example.com:8088"
SPLUNK_TOKEN="your-hec-token"

python splunk/addons/faze_security_addon.py | \
  curl -X POST $SPLUNK_HEC_URL/services/collector \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    -H "Content-Type: application/json" \
    -d @-

echo "✅ Data sent to Splunk"
```

## Troubleshooting

### Script not finding .env

The scripts search for `.env` in multiple locations:
1. `config/.env` (preferred)
2. `<script_dir>/.env`
3. `<parent_dir>/.env`

**Solution:** Place `.env` in `config/` directory or export variables:
```bash
export FAZE_API_KEY="your-key"
python agentic_red_team/fetch_agentic_red_team_vulns.py
```

### SSL certificate errors

Already handled - warnings are suppressed. If you need SSL verification:
```bash
# Modify script: change `session.verify = False` to `session.verify = True`
# Or set environment variable:
export PYTHONHTTPSVERIFY=1
```

### API key not recognized

Verify key is set and correct:
```bash
echo $FAZE_API_KEY  # Should show your key
python scripts/test_getart.py  # Test connectivity
```

### No vulnerabilities returned

Check:
1. API key is valid
2. ART ID is correct (default: 1000)
3. Internet connectivity: `curl https://api.faze.security`

```bash
# Debug request
python scripts/test_getart.py
```

## Performance Notes

- **Fetch time**: ~30-60 seconds for all 1,069 vulnerabilities
- **Memory usage**: ~50-100MB for complete dataset
- **Network**: Uses pagination with limit=100 per request

For large deployments:
- Run scripts in background: `nohup python ... > output.log 2>&1 &`
- Schedule with cron: `0 2 * * * /path/to/project/run_scan.sh`
- Use Splunk's HTTP Event Collector for reliable ingestion

## Scripts Reference

| Script | Location | Purpose |
|--------|----------|---------|
| `fetch_agentic_red_team_vulns.py` | `agentic_red_team/` | **PRIMARY**: Fetch all vulns |
| `faze_security_addon.py` | `splunk/addons/` | **PRIMARY**: Splunk integration |
| `fetch_agentic_red_team.py` | `agentic_red_team/` | Fetch last 20 vulns |
| `discover_endpoints.py` | `agentic_red_team/` | Test API endpoints |
| `test_getart.py` | `scripts/` | Test connectivity |
| `agentic_red_team_input.py` | `splunk/addons/` | Generate test data |

See `PROJECT_STRUCTURE.md` for complete file organization.
