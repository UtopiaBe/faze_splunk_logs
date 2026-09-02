#!/usr/bin/env python3
"""
Preview Script: Agentic Red Team Splunk Logs Visualization
Demonstrates how vulnerability logs appear in Splunk with formatting
"""

import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from enum import Enum


class LogFormatter:
    """Format vulnerability logs for Splunk display"""

    COLORS = {
        "CRITICAL": "\033[91m",  # Bright Red
        "HIGH": "\033[38;5;208m",  # Orange
        "MEDIUM": "\033[93m",  # Yellow
        "LOW": "\033[94m",  # Blue
        "INFO": "\033[92m",  # Green
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
    }

    SEVERITY_SYMBOLS = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "🟢 INFO",
    }

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors

    def _colorize(self, text: str, severity: str) -> str:
        """Apply color formatting based on severity"""
        if not self.use_colors:
            return text

        color_map = {
            "critical": self.COLORS["CRITICAL"],
            "high": self.COLORS["HIGH"],
            "medium": self.COLORS["MEDIUM"],
            "low": self.COLORS["LOW"],
            "info": self.COLORS["INFO"],
        }

        color = color_map.get(severity, self.COLORS["RESET"])
        return f"{color}{text}{self.COLORS['RESET']}"

    def format_table_row(
        self, timestamp: str, severity: str, target: str, vuln_type: str, description: str
    ) -> str:
        """Format log as table row"""
        severity_symbol = self.SEVERITY_SYMBOLS.get(severity, severity.upper())
        colored_severity = self._colorize(severity_symbol, severity)

        # Truncate long strings for readability
        target = target[:30].ljust(30)
        vuln_type = vuln_type[:25].ljust(25)
        description = description[:50].ljust(50)

        return f"{timestamp} | {colored_severity} | {target} | {vuln_type} | {description}"

    def format_detailed(self, event: Dict[str, Any]) -> str:
        """Format event with full details"""
        lines = []
        severity = event.get("severity", "unknown")

        # Header
        lines.append(self._colorize("=" * 100, severity))
        lines.append(
            self._colorize(
                f"🚨 VULNERABILITY DETECTED - {event.get('vulnerability_type', 'Unknown').upper()}",
                severity,
            )
        )
        lines.append(self._colorize("=" * 100, severity))

        # Key information
        lines.append(
            f"  {self.COLORS['BOLD']}Severity:{self.COLORS['RESET']} "
            f"{self._colorize(severity.upper(), severity)}"
        )
        lines.append(f"  {self.COLORS['BOLD']}Target:{self.COLORS['RESET']} {event.get('target', 'N/A')}")
        lines.append(f"  {self.COLORS['BOLD']}Time:{self.COLORS['RESET']} {event.get('timestamp', 'N/A')}")
        lines.append(
            f"  {self.COLORS['BOLD']}Session ID:{self.COLORS['RESET']} {event.get('session_id', 'N/A')}"
        )

        # Description
        lines.append(f"\n  {self.COLORS['BOLD']}Description:{self.COLORS['RESET']}")
        lines.append(f"    {event.get('description', 'No description available')}")

        # CVE Information
        cves = event.get("cve_ids", [])
        if cves and cves != []:
            lines.append(f"\n  {self.COLORS['BOLD']}Associated CVEs:{self.COLORS['RESET']}")
            for cve in cves:
                lines.append(f"    • {cve}")

        # Affected Component
        lines.append(f"\n  {self.COLORS['BOLD']}Affected Component:{self.COLORS['RESET']} {event.get('affected_component', 'Unknown')}")

        # Remediation
        lines.append(f"\n  {self.COLORS['BOLD']}Recommended Remediation:{self.COLORS['RESET']}")
        lines.append(f"    {event.get('remediation', 'Manual review required')}")

        # Priority
        priority = event.get("remediation_priority", 0)
        lines.append(f"\n  {self.COLORS['BOLD']}Remediation Priority:{self.COLORS['RESET']} {priority}/100")

        # Additional fields
        if "additional_fields" in event or len(event) > 15:
            lines.append(f"\n  {self.COLORS['BOLD']}Additional Details:{self.COLORS['RESET']}")
            for key, value in event.items():
                if key not in [
                    "timestamp",
                    "severity",
                    "target",
                    "description",
                    "cve_ids",
                    "affected_component",
                    "remediation",
                    "remediation_priority",
                    "vulnerability_type",
                    "session_id",
                    "event_type",
                    "hostname",
                    "source",
                    "detection_timestamp",
                ]:
                    if isinstance(value, (dict, list)):
                        lines.append(f"    {key}: {json.dumps(value)}")
                    else:
                        lines.append(f"    {key}: {value}")

        lines.append(self._colorize("-" * 100, severity))
        lines.append("")

        return "\n".join(lines)


class SplunkLogPreview:
    """Generate and display Splunk format logs"""

    def __init__(self):
        self.formatter = LogFormatter(use_colors=True)

    def load_addon_logs(self) -> List[Dict[str, Any]]:
        """Load logs from the add-on script"""
        try:
            # Run the addon script and capture output
            result = subprocess.run(
                [sys.executable, "bin/agentic_red_team_input.py"],
                cwd=Path(__file__).parent,
                capture_output=True,
                text=True,
            )

            events = []
            for line in result.stdout.split("\n"):
                if line.strip() and not line.startswith("#"):
                    try:
                        # Parse Splunk event format: timestamp json_data
                        parts = line.split(" ", 1)
                        if len(parts) == 2:
                            json_data = json.loads(parts[1])
                            events.append(json_data)
                    except (json.JSONDecodeError, ValueError):
                        continue

            return events
        except Exception as e:
            print(f"Error loading logs: {e}", file=sys.stderr)
            return []

    def display_logs_summary(self, events: List[Dict[str, Any]]) -> None:
        """Display summary statistics"""
        if not events:
            print("No events to display")
            return

        print("\n" + "=" * 100)
        print("📊 SPLUNK ADD-ON - AGENTIC RED TEAM VULNERABILITY DETECTION")
        print("=" * 100 + "\n")

        # Statistics
        severity_counts = {}
        type_counts = {}
        high_priority = 0

        for event in events:
            severity = event.get("severity", "unknown")
            vuln_type = event.get("vulnerability_type", "unknown")

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

            if event.get("remediation_priority", 0) >= 80:
                high_priority += 1

        print(f"📈 Total Vulnerabilities Detected: {len(events)}")
        print(f"🔴 High Priority Issues (≥80): {high_priority}\n")

        print("Severity Distribution:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                bar = "█" * count
                print(f"  {self.formatter.SEVERITY_SYMBOLS[severity]}: {bar} ({count})")

        print("\nTop Vulnerability Types:")
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_types[:5]:
            print(f"  • {vuln_type}: {count}")

    def display_table_format(self, events: List[Dict[str, Any]]) -> None:
        """Display logs in table format"""
        print("\n" + "=" * 100)
        print("📋 SPLUNK LOG TABLE VIEW")
        print("=" * 100 + "\n")

        header = "TIMESTAMP                    | SEVERITY                | TARGET                     | TYPE                     | DESCRIPTION"
        print(header)
        print("-" * 100)

        for event in events:
            row = self.formatter.format_table_row(
                timestamp=event.get("timestamp", "N/A")[:25],
                severity=event.get("severity", "unknown"),
                target=event.get("target", "N/A"),
                vuln_type=event.get("vulnerability_type", "N/A").replace("_", " "),
                description=event.get("description", "N/A"),
            )
            print(row)

        print("-" * 100 + "\n")

    def display_detailed_format(self, events: List[Dict[str, Any]]) -> None:
        """Display logs in detailed format"""
        print("\n" + "=" * 100)
        print("🔍 DETAILED VULNERABILITY REPORTS")
        print("=" * 100 + "\n")

        for i, event in enumerate(events, 1):
            print(self.formatter.format_detailed(event))

    def display_json_format(self, events: List[Dict[str, Any]]) -> None:
        """Display logs in JSON format as Splunk would store them"""
        print("\n" + "=" * 100)
        print("📄 SPLUNK JSON EVENT FORMAT")
        print("=" * 100 + "\n")

        for event in events:
            timestamp = int(datetime.fromisoformat(event["timestamp"]).timestamp())
            splunk_event = {"time": timestamp, "source": "agentic_red_team_addon", "event": event}
            print(json.dumps(splunk_event, indent=2))
            print()

    def display_search_examples(self) -> None:
        """Display example Splunk search queries"""
        print("\n" + "=" * 100)
        print("🔎 SPLUNK SEARCH QUERY EXAMPLES")
        print("=" * 100 + "\n")

        searches = [
            ("All Critical Vulnerabilities", 'sourcetype="agentic:red_team:vulnerability" severity=critical'),
            (
                "Critical + High Priority Issues",
                'sourcetype="agentic:red_team:vulnerability" severity=critical OR severity=high',
            ),
            (
                "Remote Code Execution Detections",
                'sourcetype="agentic:red_team:vulnerability" vulnerability_type=remote_code_execution',
            ),
            (
                "Exposed Secrets",
                'sourcetype="agentic:red_team:vulnerability" vulnerability_type=exposed_secrets',
            ),
            (
                "By Target with Stats",
                'sourcetype="agentic:red_team:vulnerability" | stats count by target, severity',
            ),
            (
                "Top Vulnerability Types",
                'sourcetype="agentic:red_team:vulnerability" | top vulnerability_type',
            ),
            (
                "Vulnerabilities by Hour",
                'sourcetype="agentic:red_team:vulnerability" | timechart count by severity',
            ),
            (
                "Services with CVEs",
                'sourcetype="agentic:red_team:vulnerability" cve_ids!="" | dedup affected_component',
            ),
            (
                "High Priority Actions",
                'sourcetype="agentic:red_team:vulnerability" remediation_priority>=80 | table timestamp, target, severity, remediation',
            ),
            (
                "Vulnerability Trend (Weekly)",
                'sourcetype="agentic:red_team:vulnerability" | timechart count as "Issues Detected" span=1d',
            ),
        ]

        for name, query in searches:
            print(f"• {name}")
            print(f"  Query: {query}\n")

    def display_dashboard_example(self) -> None:
        """Display example Splunk dashboard configuration"""
        print("\n" + "=" * 100)
        print("📊 SPLUNK DASHBOARD CONFIGURATION")
        print("=" * 100 + "\n")

        dashboard_config = """
Example Dashboard: "Agentic Red Team Vulnerability Monitoring"

Panels:
1. Critical Vulnerabilities Gauge
   - Search: sourcetype="agentic:red_team:vulnerability" severity=critical | stats count

2. Severity Trend Chart
   - Search: sourcetype="agentic:red_team:vulnerability" | timechart count by severity

3. Top Targets Table
   - Search: sourcetype="agentic:red_team:vulnerability" | stats count by target, severity

4. Vulnerability Type Distribution (Pie Chart)
   - Search: sourcetype="agentic:red_team:vulnerability" | stats count by vulnerability_type

5. Remediation Priority Matrix
   - Search: sourcetype="agentic:red_team:vulnerability" | stats count by severity, remediation_priority

6. Latest 50 Events Table
   - Search: sourcetype="agentic:red_team:vulnerability" | head 50 | table timestamp, target, severity, vulnerability_type, description, remediation

7. CVE Association Chart
   - Search: sourcetype="agentic:red_team:vulnerability" cve_ids!="" | stats count by vulnerability_type

8. Response Time Card
   - Search: sourcetype="agentic:red_team:vulnerability" severity=critical earliest=-1d | stats avg(response_time_seconds) as avg_response

Key Metrics to Monitor:
- Mean Time to Detection (MTTD)
- Mean Time to Response (MTTR)
- Critical Vulnerability Count
- Unpatched Service Count
- Exposed Secret Count
        """
        print(dashboard_config)

    def run(self, mode: str = "all"):
        """Run the preview with specified display mode"""
        events = self.load_addon_logs()

        if mode in ["all", "summary"]:
            self.display_logs_summary(events)

        if mode in ["all", "table"]:
            self.display_table_format(events)

        if mode in ["all", "detailed"]:
            self.display_detailed_format(events)

        if mode in ["all", "json"]:
            self.display_json_format(events)

        if mode in ["all", "searches"]:
            self.display_search_examples()

        if mode in ["all", "dashboard"]:
            self.display_dashboard_example()

        print("\n" + "=" * 100)
        print("✅ End of Splunk Log Preview")
        print("=" * 100 + "\n")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Preview Agentic Red Team Splunk logs as they would appear in Splunk"
    )
    parser.add_argument(
        "--mode",
        choices=["all", "summary", "table", "detailed", "json", "searches", "dashboard"],
        default="all",
        help="Display mode for log preview",
    )

    args = parser.parse_args()

    preview = SplunkLogPreview()
    preview.run(mode=args.mode)


if __name__ == "__main__":
    main()
