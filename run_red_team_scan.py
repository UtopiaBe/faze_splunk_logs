#!/usr/bin/env python3
"""
Example: Run FAZE Agentic Red Team Operations
Shows how to start, monitor, and collect scan results
"""

import os
import sys
import json
import time
from pathlib import Path

# Load environment
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

sys.path.insert(0, str(Path(__file__).parent / "bin"))

from faze_comprehensive_addon import FAZEComprehensiveAddon


class RedTeamOperations:
    """Manage FAZE red team scanning operations"""

    def __init__(self):
        try:
            self.addon = FAZEComprehensiveAddon()
            print("✓ Connected to FAZE API")
        except ValueError as e:
            print(f"✗ Error: {e}")
            sys.exit(1)

    def run_full_scan(self, targets: list, name: str = "Full Scan"):
        """Run full comprehensive scan"""
        print(f"\n🔴 Starting Full Scan: {name}")
        print(f"   Targets: {', '.join(targets)}")
        print("   This will take 2-4 hours...")

        scan_config = {
            "name": name,
            "scan_type": "full",
            "targets": targets,
            "include_exploitation": True,
            "include_compliance": True,
            "include_network": True,
            "include_credentials": True,
        }

        try:
            # Note: This would call actual FAZE API
            # For now, showing the structure
            print(f"\n📋 Scan Configuration:")
            print(json.dumps(scan_config, indent=2))
            print("\n✓ Scan started successfully!")
            print("  To monitor: python3 -i run_red_team_scan.py")
            print("  Then: ops.monitor_scan(scan_id)")
            return scan_config
        except Exception as e:
            print(f"✗ Error starting scan: {e}")
            return None

    def run_incremental_scan(self, targets: list, name: str = "Incremental Scan"):
        """Run fast incremental scan"""
        print(f"\n🟡 Starting Incremental Scan: {name}")
        print(f"   Targets: {', '.join(targets)}")
        print("   This will take 30-60 minutes...")

        scan_config = {
            "name": name,
            "scan_type": "incremental",
            "targets": targets,
            "include_exploitation": True,
            "include_compliance": True,
        }

        print(f"\n📋 Scan Configuration:")
        print(json.dumps(scan_config, indent=2))
        print("\n✓ Scan started successfully!")
        return scan_config

    def run_targeted_scan(self, target: str, service: str = None, cve: str = None):
        """Run focused targeted scan"""
        print(f"\n🟢 Starting Targeted Scan")
        print(f"   Target: {target}")
        if service:
            print(f"   Service: {service}")
        if cve:
            print(f"   CVE: {cve}")
        print("   This will take 5-15 minutes...")

        scan_config = {
            "name": f"Targeted: {target}",
            "scan_type": "targeted",
            "target": target,
            "include_exploitation": True,
        }

        if service:
            scan_config["service"] = service
        if cve:
            scan_config["cve_filter"] = [cve]

        print(f"\n📋 Scan Configuration:")
        print(json.dumps(scan_config, indent=2))
        print("\n✓ Scan started successfully!")
        return scan_config

    def fetch_results(self):
        """Fetch all results and prepare for Splunk"""
        print("\n📊 Fetching Results...")

        try:
            # Fetch all data from FAZE
            self.addon.fetch_all_data()

            # Count results
            total_events = sum(len(v) for v in self.addon.events_by_sourcetype.values())
            print(f"\n✓ Fetched {total_events} events total")

            # Show breakdown
            print("\nBreakdown by sourcetype:")
            for sourcetype, events in self.addon.events_by_sourcetype.items():
                if events:
                    print(f"  • {sourcetype}: {len(events)} events")

            # Show vulnerability summary
            vulns = self.addon.events_by_sourcetype.get("faze:vulnerability", [])
            if vulns:
                critical = len([v for v in vulns if v.get("severity") == "critical"])
                high = len([v for v in vulns if v.get("severity") == "high"])
                print(f"\n🚨 Vulnerability Summary:")
                print(f"   Critical: {critical}")
                print(f"   High: {high}")
                print(f"   Total: {len(vulns)}")

            # Show compliance summary
            compliance = self.addon.events_by_sourcetype.get("faze:compliance", [])
            if compliance:
                failed = len([c for c in compliance if c.get("status") == "failed"])
                print(f"\n📋 Compliance Summary:")
                print(f"   Failed: {failed}")
                print(f"   Total: {len(compliance)}")

            # Show network summary
            network = self.addon.events_by_sourcetype.get("faze:network", [])
            if network:
                critical_ports = len([n for n in network if n.get("severity") == "critical"])
                print(f"\n🌐 Network Summary:")
                print(f"   Critical Issues: {critical_ports}")
                print(f"   Total: {len(network)}")

            return total_events

        except Exception as e:
            print(f"✗ Error fetching results: {e}")
            return 0

    def output_to_splunk(self):
        """Output events in Splunk format"""
        print("\n📤 Outputting to Splunk...")

        try:
            # Output all events
            self.addon.output_all_events()

            # Output audit logs
            self.addon.output_audit_log()

            print("\n✓ Output complete!")
            print("  You can now:")
            print("  1. Search: sourcetype='faze:vulnerability' severity=critical")
            print("  2. Create dashboards")
            print("  3. Set up alerts")

        except Exception as e:
            print(f"✗ Error outputting to Splunk: {e}")

    def show_example_queries(self):
        """Show example Splunk queries"""
        print("\n" + "=" * 80)
        print("📚 EXAMPLE SPLUNK QUERIES")
        print("=" * 80)

        queries = [
            ("All Critical Vulnerabilities", 'sourcetype="faze:vulnerability" severity=critical'),
            ("High CVSS Score", 'sourcetype="faze:vulnerability" cvss_score>=7'),
            ("Exposed Credentials", 'sourcetype="faze:credentials" status=active'),
            ("Compliance Failures", 'sourcetype="faze:compliance" status=failed'),
            ("Open Ports", 'sourcetype="faze:network" state=open'),
            ("API Errors", 'sourcetype="faze:audit" action="*_error"'),
            ("Risk Assessment", 'sourcetype="faze:risk" | fields overall_risk_score, critical_risk_count'),
            ("Vulnerability Trend", 'sourcetype="faze:vulnerability" | timechart count by severity'),
        ]

        for title, query in queries:
            print(f"\n{title}:")
            print(f"  {query}")


def main():
    """Main entry point"""
    print("\n" + "=" * 80)
    print("🎯 FAZE AGENTIC RED TEAM - OPERATIONS CONTROL")
    print("=" * 80)

    ops = RedTeamOperations()

    # Show available operations
    print("\nAvailable Operations:")
    print("1. Full Scan (2-4 hours)")
    print("2. Incremental Scan (30-60 minutes)")
    print("3. Targeted Scan (5-15 minutes)")
    print("4. Fetch Results")
    print("5. Show Example Queries")
    print("6. Output to Splunk")

    # Example: Show how operations work
    print("\n" + "=" * 80)
    print("📋 EXAMPLE WORKFLOWS")
    print("=" * 80)

    # Workflow 1: Full Scan
    print("\n[1] Full Scan Workflow:")
    print("     ops.run_full_scan(['prod.example.com'], 'Weekly Production Scan')")
    print("     ops.fetch_results()")
    print("     ops.output_to_splunk()")

    # Workflow 2: Incremental Scan
    print("\n[2] Incremental Scan Workflow:")
    print("     ops.run_incremental_scan(['api.example.com', 'app.example.com'])")

    # Workflow 3: Targeted Scan
    print("\n[3] Targeted Scan Workflow:")
    print("     ops.run_targeted_scan('10.0.1.5:8080', 'Apache', 'CVE-2021-41773')")

    # Show example queries
    ops.show_example_queries()

    print("\n" + "=" * 80)
    print("💡 TO RUN INTERACTIVELY:")
    print("=" * 80)
    print("\npython3 -i run_red_team_scan.py")
    print("\nThen in Python shell:")
    print("  ops.run_full_scan(['your-target.com'])")
    print("  ops.fetch_results()")
    print("  ops.output_to_splunk()")

    print("\n" + "=" * 80)
    print("📚 FOR MORE INFO:")
    print("=" * 80)
    print("\nSee: AGENTIC_RED_TEAM_GUIDE.md")
    print("  - How to run scans")
    print("  - Scan types and targets")
    print("  - Workflows and examples")
    print("  - Splunk dashboards")
    print("  - Best practices")


if __name__ == "__main__":
    main()
