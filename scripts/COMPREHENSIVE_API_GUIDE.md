# FAZE Comprehensive API Guide

Complete reference for all FAZE API endpoints supported by the Splunk Add-on.

## Overview

The comprehensive addon includes support for 10 different sourcetypes covering all FAZE API endpoints:

1. **faze:vulnerability** - Vulnerability detection and details
2. **faze:asset** - Asset information and scan results
3. **faze:compliance** - Compliance and regulatory findings
4. **faze:network** - Network topology and open ports
5. **faze:credentials** - Exposed credentials and secrets
6. **faze:misconfiguration** - Configuration issues
7. **faze:exploit** - Known exploits and PoCs
8. **faze:risk** - Risk assessment and scoring
9. **faze:finding** - General findings
10. **faze:audit** - Audit logs and system events

## API Endpoints

### Vulnerability Endpoints

#### Get Vulnerabilities
```
Method: POST /GetVulnerabilities
Sourcetype: faze:vulnerability
```

**Request:**
```python
addon.get_vulnerabilities({
    "severity": "critical",
    "asset_id": "asset_123",
    "has_exploit": True
})
```

**Response Fields:**
- `vulnerability_id` - Unique vulnerability ID
- `type` - Vulnerability type
- `severity` - Critical/High/Medium/Low/Info
- `title` - Vulnerability title
- `description` - Detailed description
- `cve_id` - Associated CVE ID
- `cvss_score` - CVSS numeric score (0-10)
- `cvss_vector` - CVSS vector string
- `target` - Affected target
- `remediation` - Fix recommendations
- `fix_available` - Whether patch exists
- `proof_of_concept` - PoC code/link

**Splunk Query:**
```spl
sourcetype="faze:vulnerability" severity=critical
| stats count by type
| sort - count
```

#### Get Vulnerability Details
```
Method: POST /GetVulnerabilityDetails
Sourcetype: faze:vulnerability
```

**Request:**
```python
addon.get_vulnerability_details("vuln_456")
```

**Includes:** Full details including timeline, affected systems, patches.

---

### Asset Endpoints

#### Get Assets
```
Method: POST /GetAssets
Sourcetype: faze:asset
```

**Request:**
```python
addon.get_assets({
    "asset_type": "web_server",
    "status": "active"
})
```

**Response Fields:**
- `asset_id` - Unique asset ID
- `name` - Asset name
- `asset_type` - Type (web_server, database, etc.)
- `ip_address` - IP address
- `hostname` - Hostname
- `status` - Active/Inactive
- `os` - Operating system
- `services` - Running services
- `last_scanned` - Last scan timestamp
- `vulnerability_count` - Number of vulns

**Splunk Query:**
```spl
sourcetype="faze:asset" status=active
| stats count as asset_count, avg(vulnerability_count) by asset_type
```

#### Get Asset Details
```
Method: POST /GetAssetDetails
Sourcetype: faze:asset
```

Detailed asset information including full configuration, services, and patch status.

---

### Scan Endpoints

#### Get Scans
```
Method: POST /GetScans
Sourcetype: faze:asset
```

**Request:**
```python
addon.get_scans({
    "status": "completed",
    "scan_type": "full"
})
```

**Response Fields:**
- `scan_id` - Unique scan ID
- `scan_type` - Full/Incremental/Targeted
- `status` - Running/Completed/Failed
- `started_at` - Scan start time
- `completed_at` - Scan completion time
- `duration_seconds` - Scan duration
- `assets_scanned` - Number of assets
- `vulnerabilities_found` - Number of vulns

#### Get Scan Results
```
Method: POST /GetScanResults
Sourcetype: faze:asset
```

Detailed results from a specific scan including all findings.

---

### Compliance Endpoints

#### Get Compliance Findings
```
Method: POST /GetComplianceFindings
Sourcetype: faze:compliance
```

**Request:**
```python
addon.get_compliance_findings({
    "framework": "PCI-DSS",
    "status": "failed"
})
```

**Response Fields:**
- `finding_id` - Unique finding ID
- `framework` - PCI-DSS/HIPAA/SOC2/ISO27001
- `requirement_id` - Framework requirement ID
- `status` - Passed/Failed
- `severity` - Critical/High/Medium/Low
- `description` - Finding description
- `affected_systems` - Systems affected
- `remediation` - How to fix
- `evidence` - Evidence/documentation

**Splunk Query:**
```spl
sourcetype="faze:compliance" framework="PCI-DSS" status=failed
| stats count by requirement_id
```

#### Get Compliance Status
```
Method: POST /GetComplianceStatus
Sourcetype: faze:compliance
```

Overall compliance status across all frameworks.

---

### Network Endpoints

#### Get Network Findings
```
Method: POST /GetNetworkFindings
Sourcetype: faze:network
```

**Request:**
```python
addon.get_network_findings({
    "finding_type": "open_port",
    "severity": "high"
})
```

**Response Fields:**
- `finding_id` - Unique finding ID
- `finding_type` - Open port/DNS issues/Routing issues
- `severity` - Risk level
- `source_ip` - Source IP
- `dest_ip` - Destination IP
- `port` - Port number
- `protocol` - Protocol (TCP/UDP)
- `service` - Service running on port
- `risk` - Risk description

#### Get Open Ports
```
Method: POST /GetOpenPorts
Sourcetype: faze:network
```

**Request:**
```python
addon.get_open_ports("asset_123")
```

**Response Fields:**
- `port` - Port number
- `protocol` - TCP/UDP
- `state` - Open/Closed/Filtered
- `service` - Service name
- `version` - Service version
- `risk` - Exploit risk

**Splunk Query:**
```spl
sourcetype="faze:network" port < 1024
| stats count by service
```

---

### Credentials Endpoints

#### Get Exposed Credentials
```
Method: POST /GetExposedCredentials
Sourcetype: faze:credentials
```

**Request:**
```python
addon.get_exposed_credentials({
    "source": "github",
    "type": "api_key"
})
```

**Response Fields:**
- `credential_id` - Unique ID
- `type` - API key/Password/Token/SSH key
- `source` - GitHub/PublicBuckets/DarkWeb
- `username` - Associated username
- `severity` - Critical/High
- `discovered_date` - When found
- `location` - Where found
- `status` - Active/Revoked
- `affected_systems` - Systems using credential

**Splunk Query:**
```spl
sourcetype="faze:credentials" type="api_key" status=active
| stats count by source
```

---

### Misconfiguration Endpoints

#### Get Misconfigurations
```
Method: POST /GetMisconfigurations
Sourcetype: faze:misconfiguration
```

**Request:**
```python
addon.get_misconfigurations({
    "type": "weak_ssl",
    "severity": "high"
})
```

**Response Fields:**
- `config_id` - Configuration ID
- `type` - Weak SSL/Default creds/Open perms
- `severity` - Risk level
- `affected_asset` - Asset with issue
- `current_value` - Current setting
- `recommended_value` - Recommended setting
- `impact` - Impact if exploited

---

### Exploit Endpoints

#### Get Known Exploits
```
Method: POST /GetKnownExploits
Sourcetype: faze:exploit
```

**Request:**
```python
addon.get_known_exploits({
    "status": "active",
    "in_wild": True
})
```

**Response Fields:**
- `exploit_id` - Exploit ID
- `title` - Exploit title
- `type` - RCE/Privilege Escalation/etc
- `status` - Active/Patched/Mitigated
- `in_wild` - Exploited in the wild
- `difficulty` - Trivial/Easy/Medium/Hard
- `cvss_score` - Associated CVSS
- `poc_available` - PoC available
- `affected_versions` - Software versions

**Splunk Query:**
```spl
sourcetype="faze:exploit" in_wild=true difficulty=trivial
| stats count by type
```

---

### Risk Endpoints

#### Get Risk Assessment
```
Method: POST /GetRiskAssessment
Sourcetype: faze:risk
```

**Response Fields:**
- `overall_risk_score` - 0-100 risk score
- `critical_risk_count` - Number of critical issues
- `high_risk_count` - Number of high issues
- `risk_trend` - Improving/Stable/Declining
- `days_to_breach` - Estimated days to breach
- `top_risks` - List of top risks

**Splunk Query:**
```spl
sourcetype="faze:risk"
| fields overall_risk_score, critical_risk_count, days_to_breach
```

#### Get Risk Trends
```
Method: POST /GetRiskTrends
Sourcetype: faze:risk
```

**Request:**
```python
addon.get_risk_trends(days=30)
```

Historical risk data over time period.

---

## Audit Logging

All API calls are logged to the audit sourcetype (`faze:audit`):

**Audit Fields:**
- `timestamp` - When action occurred
- `action` - API action performed
- `details` - Request details
- `source` - faze_addon
- `error` - Error message if failed

**Audit Queries:**
```spl
sourcetype="faze:audit" action="get_vulnerabilities_success"
| stats count as total_calls, avg(count) as avg_vulns by action

sourcetype="faze:audit" action="*_error"
| stats count as error_count by action

sourcetype="faze:audit"
| timechart count by action
```

---

## Complete Splunk Query Examples

### Dashboard: Executive Summary
```spl
sourcetype="faze:risk" 
| fields overall_risk_score, critical_risk_count, high_risk_count
| append [search sourcetype="faze:vulnerability" severity=critical | stats count as critical_vulns]
| append [search sourcetype="faze:asset" | stats count as total_assets]
```

### Dashboard: Vulnerability Scorecard
```spl
sourcetype="faze:vulnerability"
| stats count as total, 
        count(eval(severity="critical")) as critical,
        count(eval(severity="high")) as high,
        count(eval(fix_available=true)) as fixable,
        avg(cvss_score) as avg_cvss
```

### Dashboard: Compliance Status
```spl
sourcetype="faze:compliance"
| stats count(eval(status="failed")) as failed_findings by framework
| append [search sourcetype="faze:compliance" status=passed | stats count as passed_findings by framework]
```

### Dashboard: Network Risk
```spl
sourcetype="faze:network" 
| stats count as open_ports, 
        count(eval(protocol="TCP")) as tcp_ports,
        count(eval(severity="critical")) as critical_ports
        by source_ip
| sort - critical_ports
```

---

## Rate Limiting & Performance

- **Request Timeout:** 30 seconds per API call
- **Batch Size:** Fetch all assets then get vulnerabilities per asset
- **Recommended Scan Interval:** 3600 seconds (1 hour)

## Error Handling

Errors are logged to `faze:audit` sourcetype:
- Connection errors
- Authentication failures (401)
- Rate limiting (429)
- Server errors (500)

Monitor for errors:
```spl
sourcetype="faze:audit" action="*_error"
| stats count by action
| alert if count > 10
```

---

## Configuration

See `FAZE_SETUP_GUIDE.md` for detailed configuration instructions.
