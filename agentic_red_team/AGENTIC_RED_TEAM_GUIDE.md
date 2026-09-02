# How to Use FAZE Agentic Red Team

Complete guide to running red team operations and collecting results in Splunk.

## What is FAZE Agentic Red Team?

FAZE is an **Agentic Red Team platform** that uses AI agents to simulate real-world attackers and identify vulnerabilities. It automatically:
- Scans networks and applications
- Attempts exploitation
- Reports findings with severity levels
- Suggests remediations
- Tracks compliance issues

## Getting Started

### 1. Create FAZE Account

1. Visit: https://app.faze.security
2. Sign up for an account
3. Verify email
4. Set up organization

### 2. Generate API Key

1. Log in to FAZE dashboard
2. Go to **Settings → API Keys**
3. Click **"Generate New API Key"**
4. Copy the key (format: `sk_live_xxx...`)
5. Add to `.env` file:
   ```
   FAZE_API_KEY=sk_live_your_key_here
   ```

## Red Team Operations

### Understanding Scans

FAZE supports 3 types of scans:

#### 1. **Full Scan** (Comprehensive)
- Scans all systems and services
- Takes 2-4 hours
- Finds all vulnerabilities
- **Best for:** Initial assessment, quarterly reviews

```python
# Request full scan
scan_request = {
    "scan_type": "full",
    "targets": ["10.0.0.0/24"],  # Network range
    "include_exploitation": True,
    "include_compliance": True
}
response = addon.post_scan_request(scan_request)
scan_id = response['scan_id']
```

#### 2. **Incremental Scan** (Fast)
- Scans since last scan
- Takes 30-60 minutes
- Finds new vulnerabilities
- **Best for:** Weekly/daily checks

```python
# Request incremental scan
scan_request = {
    "scan_type": "incremental",
    "targets": ["app.example.com"],
    "since_last_scan": True
}
response = addon.post_scan_request(scan_request)
```

#### 3. **Targeted Scan** (Focused)
- Scans specific service/port
- Takes 5-15 minutes
- Fast results
- **Best for:** Specific vulnerabilities, rapid response

```python
# Request targeted scan
scan_request = {
    "scan_type": "targeted",
    "target": "10.0.1.5:8080",
    "service": "Apache",
    "version": "2.4.49"
}
response = addon.post_scan_request(scan_request)
```

### Available Scan Targets

#### By IP/Network
```python
"targets": [
    "192.168.1.0/24",      # Subnet
    "10.0.1.5",            # Single IP
    "10.0.1.1-10.0.1.254"  # Range
]
```

#### By Hostname
```python
"targets": [
    "api.example.com",
    "app.example.com",
    "*.example.com"        # Wildcard
]
```

#### By Domain
```python
"targets": [
    "example.com",
    "staging.example.com"
]
```

### What FAZE Scans For

**Vulnerability Categories:**
- Remote Code Execution (RCE)
- SQL Injection
- Cross-Site Scripting (XSS)
- Authentication Bypass
- Privilege Escalation
- Weak Cryptography
- Exposed Secrets
- Misconfigurations
- Unpatched Services
- Default Credentials

**Network Issues:**
- Open Ports
- Exposed Services
- Weak SSL/TLS
- DNS Issues
- Network Exposure

**Compliance:**
- PCI-DSS
- HIPAA
- SOC2
- ISO 27001
- CIS Benchmarks

**Credentials:**
- Exposed API Keys
- Hardcoded Passwords
- Private Keys
- Database Credentials

## Running a Red Team Operation

### Step 1: Create Scan

```python
# Create addon instance
from faze_comprehensive_addon import FAZEComprehensiveAddon
addon = FAZEComprehensiveAddon()

# Request scan
scan_config = {
    "name": "Weekly Production Scan",
    "scan_type": "incremental",
    "targets": ["prod.example.com"],
    "include_exploitation": True,
    "include_compliance": True,
    "severity_threshold": "low",
    "schedule": {
        "frequency": "weekly",
        "day": "monday",
        "time": "02:00"  # 2 AM UTC
    }
}

# Start scan
scan_response = addon.create_scan(scan_config)
scan_id = scan_response['scan_id']
print(f"Scan started: {scan_id}")
```

### Step 2: Monitor Progress

```python
# Check scan status
import time

while True:
    status = addon.get_scan_status(scan_id)
    print(f"Status: {status['status']}")
    print(f"Progress: {status['progress']}%")
    print(f"Vulnerabilities found: {status['vulnerability_count']}")
    
    if status['status'] == 'completed':
        break
    
    time.sleep(60)  # Check every minute
```

### Step 3: Fetch Results

```python
# Get scan results
results = addon.get_scan_results(scan_id)

# Extract findings
vulnerabilities = results['vulnerabilities']
compliance_findings = results['compliance_findings']
network_findings = results['network_findings']
credentials = results['exposed_credentials']

print(f"Found {len(vulnerabilities)} vulnerabilities")
print(f"Found {len(compliance_findings)} compliance issues")
```

### Step 4: Send to Splunk

```python
# Fetch all data through addon
addon.fetch_all_data()

# Output Splunk events
addon.output_all_events()

# Output audit logs
addon.output_audit_log()
```

## Common Workflows

### Workflow 1: Weekly Production Scan

```bash
#!/bin/bash
# Weekly production scan

export FAZE_API_KEY='sk_live_xxx'

# Run scan
python3 << 'EOF'
from faze_comprehensive_addon import FAZEComprehensiveAddon

addon = FAZEComprehensiveAddon()

# Start weekly scan
scan = addon.create_scan({
    "name": "Weekly Production",
    "scan_type": "incremental",
    "targets": ["prod.example.com", "api.example.com"],
    "include_exploitation": True
})

print(f"Scan {scan['scan_id']} started")
EOF
```

### Workflow 2: Hourly Compliance Check

```bash
#!/bin/bash
# Hourly compliance check

export FAZE_API_KEY='sk_live_xxx'

python3 << 'EOF'
from faze_comprehensive_addon import FAZEComprehensiveAddon

addon = FAZEComprehensiveAddon()

# Get compliance status
compliance = addon.get_compliance_status()

# Get critical findings
critical = addon.get_compliance_findings({
    "severity": "critical"
})

print(f"Critical compliance issues: {len(critical)}")

# Send to Splunk
addon.fetch_all_data()
addon.output_all_events()
EOF
```

### Workflow 3: On-Demand Targeted Scan

```bash
#!/bin/bash
# Run targeted scan for specific vulnerability

export FAZE_API_KEY='sk_live_xxx'

# Scan for specific CVE
python3 << 'EOF'
from faze_comprehensive_addon import FAZEComprehensiveAddon

addon = FAZEComprehensiveAddon()

# Scan for CVE-2021-41773 (Apache RCE)
scan = addon.create_scan({
    "name": "Apache CVE-2021-41773 Check",
    "scan_type": "targeted",
    "targets": ["10.0.1.5:80"],
    "cve_filter": ["CVE-2021-41773"],
    "include_exploitation": True
})

print(f"Scan {scan['scan_id']} started")
EOF
```

### Workflow 4: Continuous Monitoring

```python
# continuous_monitor.py
import time
from faze_comprehensive_addon import FAZEComprehensiveAddon

addon = FAZEComprehensiveAddon()

# Monitor every 6 hours
while True:
    print("Fetching vulnerability data...")
    
    # Get latest vulnerabilities
    vulns = addon.get_vulnerabilities({"severity": "critical"})
    
    if vulns:
        print(f"⚠️ ALERT: {len(vulns)} critical vulnerabilities!")
        for vuln in vulns:
            print(f"  - {vuln['title']} (CVE: {vuln.get('cve_id')})")
    
    # Fetch all data
    addon.fetch_all_data()
    addon.output_all_events()
    
    # Wait 6 hours
    time.sleep(6 * 3600)
```

## Splunk Dashboards for Red Team Operations

### Dashboard 1: Active Scans

```spl
sourcetype="faze:asset" status=running
| stats count by scan_type, progress
| gauge 0 100
```

### Dashboard 2: Critical Vulnerabilities

```spl
sourcetype="faze:vulnerability" severity=critical
| stats count as total,
        count(eval(fix_available=true)) as fixable,
        avg(cvss_score) as avg_cvss
| eval fix_rate=round(fixable/total*100, 2)
```

### Dashboard 3: Red Team Activity

```spl
sourcetype="faze:audit"
| timechart count by action
| rename action as "Red Team Action"
```

### Dashboard 4: Compliance Posture

```spl
sourcetype="faze:compliance"
| stats count(eval(status="failed")) as failed,
        count(eval(status="passed")) as passed
        by framework
| eval compliance_rate=round(passed/(passed+failed)*100, 2)
```

### Dashboard 5: Network Exposure

```spl
sourcetype="faze:network"
| stats count as open_ports,
        count(eval(severity="critical")) as critical,
        count(eval(severity="high")) as high
        by source_ip
| sort - critical
```

## API Endpoints for Red Team Operations

### Create Scan
```
POST /CreateScan
{
  "name": "Scan name",
  "scan_type": "full|incremental|targeted",
  "targets": ["target1", "target2"],
  "include_exploitation": true,
  "include_compliance": true
}
```

### Get Scan Status
```
POST /GetScanStatus
{
  "scan_id": "scan_123"
}
Response:
{
  "status": "running|completed|failed",
  "progress": 45,
  "vulnerability_count": 12,
  "started_at": "2024-10-08T10:00:00Z",
  "estimated_completion": "2024-10-08T12:00:00Z"
}
```

### Cancel Scan
```
POST /CancelScan
{
  "scan_id": "scan_123"
}
```

### Schedule Recurring Scan
```
POST /ScheduleScan
{
  "name": "Weekly Scan",
  "scan_config": {...},
  "schedule": {
    "frequency": "weekly",
    "day": "monday",
    "time": "02:00"
  }
}
```

## Best Practices

### Security
- ✅ Use API key with minimal permissions
- ✅ Rotate API keys quarterly
- ✅ Never commit API keys to git
- ✅ Use `.env` for local development
- ✅ Use Splunk credential store for production

### Scanning
- ✅ Schedule scans during maintenance windows
- ✅ Start with targeted scans
- ✅ Run full scans monthly
- ✅ Use incremental scans weekly
- ✅ Monitor scan impact on systems

### Remediation
- ✅ Address critical issues within 24 hours
- ✅ Track remediation progress in Splunk
- ✅ Verify fixes with re-scan
- ✅ Update audit trail
- ✅ Document all changes

### Monitoring
- ✅ Set up alerts for critical findings
- ✅ Monitor API usage
- ✅ Track scan completion times
- ✅ Review trends weekly
- ✅ Share reports with leadership

## Troubleshooting

### Scan Not Starting
```python
# Check if targets are reachable
addon.verify_target_connectivity("target_ip")

# Check for scan quota
quota = addon.get_scan_quota()
print(f"Scans remaining: {quota['remaining']}")
```

### Results Not Showing
```python
# Wait for scan to complete
status = addon.get_scan_status(scan_id)
if status['status'] != 'completed':
    print(f"Scan still running: {status['progress']}%")

# Check for errors
if status['status'] == 'failed':
    print(f"Scan failed: {status['error_message']}")
```

### High False Positives
```python
# Adjust confidence threshold
addon.update_scan_settings({
    "confidence_threshold": 0.8,  # 80% confidence minimum
    "exclude_paths": ["/admin/test", "/staging"]
})
```

## Next Steps

1. **Get API Key** - https://app.faze.security/settings/api-keys
2. **Create first scan** - Start with targeted scan
3. **Monitor results** - Use `splunk_log_explorer.py`
4. **Set up Splunk** - Configure HEC or file input
5. **Create dashboards** - Use examples above
6. **Schedule recurring scans** - Set up weekly/daily
7. **Automate remediation** - Use Splunk alerts

---

## Resources

- FAZE Platform: https://app.faze.security
- FAZE Docs: https://docs.faze.security
- API Reference: https://docs.faze.security/api
- Support: support@faze.security
