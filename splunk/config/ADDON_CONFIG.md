# FAZE Agentic Red Team Splunk Addon

## Configuration

The addon fetches all vulnerabilities from FAZE Agentic Red Team platform and outputs them in Splunk-compatible JSON format.

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FAZE_API_KEY` | Yes | - | API key for FAZE Security API |
| `FAZE_ART_ID` | No | `1000` | Agentic Red Team ID |
| `FAZE_DEDUP_VULNS` | No | `false` | Enable deduplication by asset_name |

### Deduplication

Set `FAZE_DEDUP_VULNS=true` to enable deduplication:

```bash
export FAZE_API_KEY="your-api-key"
export FAZE_ART_ID="1000"
export FAZE_DEDUP_VULNS="true"
python3 bin/faze_security_addon.py
```

**What it does:**
- When enabled, only the **first occurrence** of each vulnerability type per asset is indexed
- Duplicate vulnerabilities on the same asset are skipped
- Deduplication is tracked by `(asset_name, vulnerability_name)` tuple
- Statistics show how many duplicates were skipped

**Output:**
```
Fetching ART vulnerabilities for art_id=1000...
Deduplication enabled - showing only first occurrence per asset
Fetching assets...
Found 121 assets
Fetching vulnerabilities...
Found 123 vulnerability groups

Complete! Fetched 847 vulnerabilities
Deduplicated 222 duplicate entries
```

### Usage

**Without deduplication (default):**
```bash
export FAZE_API_KEY="your-api-key-here"
python3 bin/faze_security_addon.py
```

**With deduplication enabled:**
```bash
export FAZE_API_KEY="your-api-key-here"
export FAZE_DEDUP_VULNS="true"
python3 bin/faze_security_addon.py
```

### Output Format

Each vulnerability is output as JSONL:

```json
{
  "timestamp": "2026-09-02T11:34:34.477028+00:00",
  "event_type": "vulnerability",
  "sourcetype": "faze:agentic_red_team",
  "vulnerability_id": 15634,
  "vulnerability_name": "Internal Service Context Embedded in Account Activation Token (Information Disclosure)",
  "severity": "High",
  "asset_id": 1082,
  "asset_name": "developer-nonprod.discountbank.co.il",
  "action": "https://developer-nonprod.discountbank.co.il/openapi/user/register",
  "method": "POST",
  "key": null,
  "token": null,
  "fixed": false,
  "last_date": "16-08-2026 | 11:43:53",
  "discovery_rank": null
}
```

### Splunk Integration

For Splunk HTTP Event Collector (HEC):

```bash
python3 bin/faze_security_addon.py | \
  curl -X POST https://splunk-hec.example.com:8088/services/collector \
  -H "Authorization: Splunk your-hec-token" \
  -d @-
```

Or directly via Splunk input:

```bash
python3 bin/faze_security_addon.py | splunk add oneshot stdin://
```

### Statistics

Stderr output includes:
- Number of assets fetched
- Number of vulnerability groups found
- Number of total vulnerabilities
- (If dedup enabled) Number of duplicates removed
