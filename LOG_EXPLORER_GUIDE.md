# Splunk Log Explorer - Local Query Tool Guide

Query and filter FAZE logs locally using Python with Splunk-like syntax.

## Overview

The Splunk Log Explorer is a local Python tool that lets you:
- Query FAZE logs from the command line
- Filter by sourcetype, severity, CVSS score, and custom fields
- Sort and limit results
- Select specific fields to display
- Test queries before running in Splunk

## Installation

```bash
# Dependencies already installed
pip install python-dotenv requests

# Copy and configure .env
cp .env.example .env
# Add your FAZE_API_KEY to .env
```

## Quick Start

### 1. Run with default examples
```bash
python3 splunk_log_explorer.py
```

Shows:
- Available sourcetypes
- Available fields
- 7 example queries

### 2. Use interactively

```bash
python3 -i splunk_log_explorer.py
```

Then in Python shell:
```python
# Create explorer instance
explorer = SplunkLogExplorer(events)

# Build a query
q = explorer.query().sourcetype('faze:vulnerability').where('severity', '==', 'critical')
results = q.execute(events)

# Display results
for r in results:
    print(json.dumps(r, indent=2))
```

## Query Syntax

### Basic Query Structure

```python
query = (explorer.query()
    .sourcetype('sourcetype_name')           # Filter by sourcetype
    .where('field', 'operator', 'value')     # Add conditions
    .fields('field1', 'field2')              # Select fields
    .sort('field_name', desc=True)           # Sort results
    .limit(10)                               # Limit results
    .execute(events)                         # Execute query
)
```

### Sourcetypes

Available sourcetypes:
```python
'faze:vulnerability'      # Vulnerability findings
'faze:asset'             # Asset information
'faze:compliance'        # Compliance findings
'faze:network'           # Network findings
'faze:credentials'       # Exposed credentials
'faze:misconfiguration'  # Configuration issues
'faze:exploit'           # Known exploits
'faze:risk'              # Risk assessments
'faze:audit'             # Audit logs
```

### Comparison Operators

```python
'=='         # Equal
'!='         # Not equal
'>'          # Greater than
'>='         # Greater than or equal
'<'          # Less than
'<='         # Less than or equal
'LIKE'       # Regex match
'NOT LIKE'   # Regex not match
'IN'         # In list
'NOT IN'     # Not in list
```

## Example Queries

### 1. Critical Vulnerabilities

```python
q = (explorer.query()
    .sourcetype('faze:vulnerability')
    .where('severity', '==', 'critical')
    .sort('cvss_score', desc=True)
    .limit(10)
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:vulnerability" severity=critical
| sort - cvss_score
| head 10
```

### 2. High CVSS Score

```python
q = (explorer.query()
    .sourcetype('faze:vulnerability')
    .where('cvss_score', '>=', 7.0)
    .fields('title', 'cvss_score', 'severity', 'remediation')
    .limit(20)
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:vulnerability" cvss_score>=7
| fields title, cvss_score, severity, remediation
| head 20
```

### 3. Exposed Credentials

```python
q = (explorer.query()
    .sourcetype('faze:credentials')
    .where('status', '==', 'active')
    .where('type', 'IN', ['api_key', 'password', 'token'])
    .sort('discovered_date', desc=True)
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:credentials" status=active (type=api_key OR type=password OR type=token)
| sort - discovered_date
```

### 4. Network Issues on Specific Port

```python
q = (explorer.query()
    .sourcetype('faze:network')
    .where('port', 'IN', [22, 23, 3306, 5432])
    .where('severity', '>', 'low')
    .fields('source_ip', 'dest_ip', 'port', 'service')
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:network" (port=22 OR port=23 OR port=3306 OR port=5432) severity>low
| fields source_ip, dest_ip, port, service
```

### 5. Compliance Failures

```python
q = (explorer.query()
    .sourcetype('faze:compliance')
    .where('status', '==', 'failed')
    .where('framework', 'LIKE', 'PCI')
    .sort('requirement_id', desc=False)
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:compliance" status=failed framework="*PCI*"
| sort requirement_id
```

### 6. Misconfigurations by Type

```python
q = (explorer.query()
    .sourcetype('faze:misconfiguration')
    .sort('severity', desc=True)
    .limit(100)
)
results = q.execute(events)

# Count by type
from collections import Counter
types = Counter(r.get('type') for r in results)
print(types)
```

**Splunk equivalent:**
```spl
sourcetype="faze:misconfiguration"
| stats count by type
| sort - count
```

### 7. Known Exploits in the Wild

```python
q = (explorer.query()
    .sourcetype('faze:exploit')
    .where('in_wild', '==', True)
    .where('difficulty', 'LIKE', 'Trivial|Easy')
    .fields('title', 'type', 'difficulty', 'cvss_score')
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:exploit" in_wild=true (difficulty=Trivial OR difficulty=Easy)
| fields title, type, difficulty, cvss_score
```

### 8. Risk Assessment Trending

```python
q = (explorer.query()
    .sourcetype('faze:risk')
    .fields('timestamp', 'overall_risk_score', 'critical_risk_count', 'risk_trend')
    .sort('timestamp', desc=True)
)
results = q.execute(events)

# Show trend
for r in results[:10]:
    print(f"{r['timestamp']}: Score={r['overall_risk_score']}, Critical={r['critical_risk_count']}")
```

**Splunk equivalent:**
```spl
sourcetype="faze:risk"
| fields timestamp, overall_risk_score, critical_risk_count, risk_trend
| timechart avg(overall_risk_score)
```

### 9. Audit Log Errors

```python
q = (explorer.query()
    .sourcetype('faze:audit')
    .where('action', 'LIKE', '_error$')
    .sort('timestamp', desc=True)
    .limit(50)
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:audit" action="*_error"
| sort - timestamp
| head 50
```

### 10. Assets with Multiple Issues

```python
q = (explorer.query()
    .sourcetype('faze:asset')
    .where('vulnerability_count', '>', 5)
    .sort('vulnerability_count', desc=True)
    .fields('name', 'asset_type', 'vulnerability_count', 'last_scanned')
)
results = q.execute(events)
```

**Splunk equivalent:**
```spl
sourcetype="faze:asset" vulnerability_count>5
| sort - vulnerability_count
| fields name, asset_type, vulnerability_count, last_scanned
```

## Advanced Features

### Multiple Where Clauses

```python
q = (explorer.query()
    .sourcetype('faze:vulnerability')
    .where('severity', '==', 'critical')
    .where('cvss_score', '>=', 8.0)
    .where('fix_available', '==', True)
)
results = q.execute(events)
```

### Field Selection

```python
q = (explorer.query()
    .sourcetype('faze:vulnerability')
    .fields('vulnerability_id', 'title', 'severity', 'cvss_score')  # Only show these
)
results = q.execute(events)
```

### Sorting

```python
# Descending (default)
q = explorer.query().sort('cvss_score', desc=True)

# Ascending
q = explorer.query().sort('title', desc=False)
```

### Limiting Results

```python
# Get top 10
q = explorer.query().limit(10)

# Get top 100
q = explorer.query().limit(100)
```

## Processing Results

### Print as JSON
```python
for result in results:
    print(json.dumps(result, indent=2))
```

### Filter in memory
```python
high_risk = [r for r in results if r.get('cvss_score', 0) >= 8]
```

### Statistics
```python
from collections import Counter

# Count by severity
severity_counts = Counter(r.get('severity') for r in results)
print(severity_counts)

# Average CVSS
avg_cvss = sum(r.get('cvss_score', 0) for r in results) / len(results)
print(f"Average CVSS: {avg_cvss}")
```

### Export to CSV
```python
import csv

with open('results.csv', 'w') as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)
```

## Comparison: Python vs Splunk

| Task | Python Query | Splunk Query |
|------|--------------|-------------|
| Filter by severity | `.where('severity', '==', 'critical')` | `severity=critical` |
| Greater than | `.where('cvss_score', '>', 7)` | `cvss_score>7` |
| Pattern match | `.where('title', 'LIKE', 'RCE')` | `title="*RCE*"` |
| Multiple values | `.where('type', 'IN', ['a', 'b'])` | `(type=a OR type=b)` |
| Select fields | `.fields('a', 'b', 'c')` | `\| fields a, b, c` |
| Limit | `.limit(10)` | `\| head 10` |
| Sort | `.sort('field', desc=True)` | `\| sort - field` |

## Tips & Tricks

1. **Test queries locally first** - Verify results before running in Splunk
2. **Use field selection** - Reduce output size with `.fields()`
3. **Sort before limit** - Sort then limit to get top N
4. **Chain queries** - Build complex queries by chaining methods
5. **Debug with print** - Print intermediate results to understand data

## Troubleshooting

**"No events found"**
- Verify FAZE_API_KEY is set
- Check if assets have been scanned in FAZE
- Verify sourcetype name is correct

**"Connection refused"**
- Check FAZE_API_URL is accessible
- Verify network/firewall allows outbound HTTPS

**"Unexpected field values"**
- Use `.fields()` to inspect available fields first
- Print sample event to see structure

## Performance Considerations

- Queries execute on all events in memory
- For large datasets (>10K events), filter with `.sourcetype()` and `.where()` early
- `.limit()` stops processing once limit is reached
- Results are not paginated - all results loaded at once

---

## See Also

- `COMPREHENSIVE_API_GUIDE.md` - All API endpoints
- `README.md` - Main documentation
- `QUICK_START.md` - Quick setup guide
