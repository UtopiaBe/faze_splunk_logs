# Agentic Red Team Vulnerability Detection Add-on for Splunk

A comprehensive Splunk Add-on for capturing, analyzing, and monitoring vulnerabilities detected during Agentic Red Team operations. This add-on provides real-time vulnerability detection, severity-based prioritization, and remediation tracking.

## Features

### Core Capabilities
- **Comprehensive Vulnerability Detection**: 15+ vulnerability types including RCE, SQL Injection, XSS, Auth Bypass, Privilege Escalation, and more
- **Multi-Level Severity Classification**: Critical, High, Medium, Low, and Informational
- **CVE Association**: Automatic linking of detected vulnerabilities to CVE IDs
- **Remediation Tracking**: Built-in remediation recommendations and priority scoring
- **Session-Based Correlation**: All vulnerabilities from a single red team operation tracked together
- **Real-Time Alerting**: Immediate notification of critical issues

### Vulnerability Types Detected
1. **Remote Code Execution (RCE)** - Execution of arbitrary code
2. **SQL Injection** - Database query manipulation
3. **Cross-Site Scripting (XSS)** - Client-side script injection
4. **Authentication Bypass** - Circumventing authentication mechanisms
5. **Privilege Escalation** - Unauthorized privilege elevation
6. **Weak Cryptography** - Insufficient encryption or hashing
7. **Exposed Secrets** - Hardcoded credentials and API keys
8. **Insecure Deserialization** - Unsafe object reconstruction
9. **Server-Side Request Forgery (SSRF)** - Internal request manipulation
10. **XML External Entity (XXE)** - XML parsing vulnerabilities
11. **Path Traversal** - Unauthorized file system access
12. **Weak File Permissions** - Insufficient file access controls
13. **Unpatched Services** - Running vulnerable software versions
14. **Default Credentials** - Unchanged default passwords
15. **Sensitive Data Exposure** - Unprotected confidential information

## Installation

### Prerequisites
- Splunk Enterprise 8.0+ or Splunk Cloud
- Python 3.6+ (for the add-on script)
- Linux/Unix or Windows environment

### Installation Steps

1. **Download and Extract**
   ```bash
   cd $SPLUNK_HOME/etc/apps/
   git clone https://github.com/utopiabe/faze_splunk_logs.git agentic-red-team
   cd agentic-red-team
   ```

2. **Set Permissions**
   ```bash
   chmod +x bin/agentic_red_team_input.py
   chown -R splunk:splunk $SPLUNK_HOME/etc/apps/agentic-red-team
   ```

3. **Restart Splunk**
   ```bash
   $SPLUNK_HOME/bin/splunk restart
   ```

4. **Verify Installation**
   - Navigate to Settings → Data Inputs → Scripts
   - You should see "agentic_red_team_input.py" listed as an active input

## Configuration

### Input Configuration (`default/inputs.conf`)

The add-on runs every hour by default and indexes vulnerabilities to the `security` index:

```conf
[agentic_red_team://default]
disabled = 0                          # Enable/disable the input
interval = 3600                       # Run every 3600 seconds (1 hour)
sourcetype = agentic:red_team:vulnerability
index = security                      # Target index
python.version = python3              # Python version
```

### Custom Configuration

Create `local/inputs.conf` to override defaults:

```conf
[agentic_red_team://default]
interval = 1800                       # Run every 30 minutes
index = my_custom_security_index      # Use different index
```

## Usage

### Running the Add-on Directly

Test the add-on without Splunk:

```bash
python3 bin/agentic_red_team_input.py
```

Expected output: Splunk-formatted vulnerability events in JSON format.

### Preview Logs in Terminal

View how logs appear in Splunk with interactive formatting:

```bash
# Show all views
python3 preview_splunk_logs.py

# Show specific view
python3 preview_splunk_logs.py --mode summary   # Statistics only
python3 preview_splunk_logs.py --mode table     # Table format
python3 preview_splunk_logs.py --mode detailed  # Full details
python3 preview_splunk_logs.py --mode json      # Raw JSON
python3 preview_splunk_logs.py --mode searches  # Example queries
python3 preview_splunk_logs.py --mode dashboard # Dashboard examples
```

## Splunk Queries

### Pre-Built Searches

#### Critical Vulnerabilities Only
```spl
sourcetype="agentic:red_team:vulnerability" severity=critical
```

#### High-Priority Issues (within 24 hours)
```spl
sourcetype="agentic:red_team:vulnerability" severity=critical OR severity=high
earliest=-24h
```

#### Remote Code Execution Detections
```spl
sourcetype="agentic:red_team:vulnerability" 
vulnerability_type=remote_code_execution
```

#### Exposed Secrets
```spl
sourcetype="agentic:red_team:vulnerability" 
vulnerability_type=exposed_secrets
```

#### Vulnerability Statistics by Target
```spl
sourcetype="agentic:red_team:vulnerability" 
| stats count by target, severity
| sort - count
```

#### Top Vulnerability Types
```spl
sourcetype="agentic:red_team:vulnerability" 
| top vulnerability_type
```

#### Vulnerabilities with CVEs
```spl
sourcetype="agentic:red_team:vulnerability" 
cve_ids!="" 
| table timestamp, target, cve_ids, remediation
```

#### Remediation Priority Report
```spl
sourcetype="agentic:red_team:vulnerability" 
remediation_priority >= 80 
| table timestamp, target, severity, affected_component, remediation
| sort - remediation_priority
```

#### Time-Based Trend
```spl
sourcetype="agentic:red_team:vulnerability" 
| timechart count by severity span=1d
```

#### Unpatched Services Report
```spl
sourcetype="agentic:red_team:vulnerability" 
vulnerability_type=unpatched_service 
| stats count by affected_component, severity
```

### Alert Rules

#### Alert on Any Critical Vulnerability
```
Name: Critical Vulnerability Detected
Search: sourcetype="agentic:red_team:vulnerability" severity=critical
Trigger: On every match
Action: Email to security-team@company.com
```

#### Alert on Exposed Secrets
```
Name: Exposed Secrets Detected
Search: sourcetype="agentic:red_team:vulnerability" vulnerability_type=exposed_secrets
Trigger: On every match
Action: Slack notification + Email + PagerDuty trigger
```

#### Alert on Multiple High-Severity Issues in Short Timeframe
```
Name: Vulnerability Spike Detected
Search: sourcetype="agentic:red_team:vulnerability" severity=high OR severity=critical
        | stats count as vulnerability_count by session_id
        | where vulnerability_count > 5
Trigger: On every match
Action: Email to CISO + Escalate to incident management
```

## Event Fields

Each vulnerability event contains the following fields:

| Field | Type | Description |
|-------|------|-------------|
| timestamp | datetime | Event creation time (ISO 8601) |
| event_type | string | Type of event (always "vulnerability_detection") |
| session_id | string | Unique red team operation session ID |
| vulnerability_type | string | Category of vulnerability detected |
| severity | string | Severity level (critical, high, medium, low, info) |
| target | string | Target of vulnerability (IP, hostname, service, path) |
| description | string | Detailed description of vulnerability |
| cve_ids | array | Associated CVE identifiers |
| affected_component | string | Component affected by vulnerability |
| remediation | string | Recommended remediation steps |
| hostname | string | Host running the detection |
| source | string | Source system (always "agentic_red_team") |
| remediation_priority | integer | Priority score (1-100) |
| detection_timestamp | datetime | When vulnerability was detected |

### Example Event

```json
{
  "timestamp": "2024-01-15T14:23:45.123456",
  "event_type": "vulnerability_detection",
  "session_id": "a1b2c3d4e5f6",
  "vulnerability_type": "remote_code_execution",
  "severity": "critical",
  "target": "192.168.1.100:9200",
  "description": "Unauthenticated remote code execution in Elasticsearch",
  "cve_ids": ["CVE-2023-5678"],
  "affected_component": "Elasticsearch Service",
  "remediation": "Update to patched version and enable authentication",
  "hostname": "red-team-scanner",
  "source": "agentic_red_team",
  "remediation_priority": 100,
  "detection_timestamp": "2024-01-15T14:23:45.123456",
  "service": "Elasticsearch",
  "version": "7.10.0",
  "exploit_available": true
}
```

## Dashboards

### Recommended Dashboard Panels

#### 1. Critical Vulnerability Gauge
Shows count of critical vulnerabilities with red/orange/green status indicators.

#### 2. Severity Distribution Pie Chart
Visualizes the breakdown of vulnerabilities by severity level.

#### 3. Top Affected Targets Table
Lists systems with the most vulnerabilities, filterable by severity.

#### 4. Vulnerability Type Trend (Time Chart)
Shows how different vulnerability types are trending over time.

#### 5. Remediation Status Cards
- Total vulnerabilities requiring immediate action
- Vulnerabilities with available patches
- Unresolved critical issues

#### 6. Latest Events Table
Most recent 50 vulnerability detections with full details.

#### 7. Session-Based Correlations
Group vulnerabilities by red team session for operation tracking.

#### 8. Remediation Efficiency Metrics
- Mean Time to Remediation (MTTR)
- Issues remediated vs. outstanding
- Remediation rate by severity

## Advanced Features

### Session Correlation
All vulnerabilities from a single red team operation share the same `session_id`, allowing for comprehensive operation analysis:

```spl
sourcetype="agentic:red_team:vulnerability" session_id=a1b2c3d4e5f6
| timechart count by severity
```

### Custom Field Extraction
The add-on uses automatic KV extraction and JSON parsing. Additional fields can be extracted in `props.conf`:

```conf
EXTRACT-custom_field = "custom_field":\s*"(?<custom_field>[^"]+)"
```

### Lookup Tables
Pre-built lookups for severity levels and vulnerability types enable enrichment:

- `severity_levels.csv` - Maps severity to action priority
- `vulnerability_types.csv` - Maps vulnerability types to OWASP/MITRE categories

### Alert Suppression
Deduplicate repeated vulnerabilities on the same target:

```spl
sourcetype="agentic:red_team:vulnerability" 
| dedup target, vulnerability_type 
| stats count by target, severity
```

## Troubleshooting

### Logs Not Appearing

1. **Check input status:**
   ```
   Settings → Data Inputs → Scripts → agentic_red_team_input.py
   ```

2. **Verify Python availability:**
   ```bash
   which python3
   python3 --version
   ```

3. **Check Splunk logs:**
   ```
   $SPLUNK_HOME/var/log/splunk/splunkd.log
   ```

### Wrong Index

1. Edit `local/inputs.conf`
2. Set correct index name
3. Restart Splunk

### Slow Performance

1. Increase interval in `inputs.conf` (e.g., 7200 for 2 hours)
2. Filter specific vulnerability types in the input script
3. Use summary indexing for archived data

## Performance Tuning

### For Large Environments

Modify `bin/agentic_red_team_input.py` to focus on specific vulnerability types:

```python
# Only scan for critical issues in production
VULNERABILITY_TYPES_TO_CHECK = [
    VulnerabilityType.RCE,
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.EXPOSED_SECRETS,
]
```

### Indexing Strategy

Separate indices for different severity levels:

```conf
[agentic_red_team://critical]
index = security_critical
EXTRACT-severity_filter = severity=critical

[agentic_red_team://high]
index = security_high
EXTRACT-severity_filter = severity=high
```

## Integration with Other Splunk Add-ons

### Works With
- **Splunk Security Essentials (SSE)** - Use vulnerability data in compliance reports
- **Splunk Enterprise Security (ES)** - Correlate with other security data
- **Splunk User Behavior Analytics (UBA)** - Detect suspicious patterns
- **PagerDuty/ServiceNow** - Alert routing and ticketing

### Compatible Data Models
- CIM (Common Information Model) Threat Intelligence
- MITRE ATT&CK Framework
- OWASP Top 10 Categories

## API Reference

### AgenticRedTeamAddon Class

#### Methods

**`add_vulnerability()`**
```python
add_vulnerability(
    vuln_type: VulnerabilityType,
    severity: VulnerabilitySeverity,
    target: str,
    description: str,
    cve_ids: Optional[List[str]] = None,
    affected_component: Optional[str] = None,
    remediation: Optional[str] = None,
    additional_fields: Optional[Dict[str, Any]] = None
) -> None
```

**`run_system_scans()`**
```python
run_system_scans() -> None
```
Executes all built-in vulnerability scans.

**`generate_splunk_events()`**
```python
generate_splunk_events() -> List[str]
```
Converts vulnerability data to Splunk event format.

**`get_summary_statistics()`**
```python
get_summary_statistics() -> Dict[str, Any]
```
Returns aggregate statistics about detected vulnerabilities.

## Contributing

To extend the add-on with custom vulnerability detection:

1. Subclass `AgenticRedTeamAddon`
2. Override `run_system_scans()`
3. Call `add_vulnerability()` for detected issues
4. Test with `preview_splunk_logs.py`

Example:
```python
class CustomRedTeamAddon(AgenticRedTeamAddon):
    def run_system_scans(self):
        super().run_system_scans()
        self._scan_custom_targets()
    
    def _scan_custom_targets(self):
        # Your custom scanning logic
        self.add_vulnerability(...)
```

## Version History

### v2.0.0 (Current)
- Complete rewrite with Agentic Red Team focus
- 15 vulnerability types
- Session-based correlation
- Enhanced field extraction
- Comprehensive documentation

### v1.0.0 (Initial Release)
- Basic vulnerability detection
- 5 vulnerability types
- Simple field extraction

## License

This add-on is provided as-is for security research and authorized red team operations.

## Support

For issues, questions, or contributions:
- GitHub Issues: [faze_splunk_logs/issues](https://github.com/utopiabe/faze_splunk_logs/issues)
- Email: agentic-red-team@company.com

## Disclaimer

This add-on is designed for authorized red team operations and security research. Use only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.
