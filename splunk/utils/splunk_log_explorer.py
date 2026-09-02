#!/usr/bin/env python3
"""
Splunk Log Explorer - Local Python tool to query and filter FAZE logs
Mimics Splunk search syntax and functionality
"""

import os
import json
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

# Add bin directory to path
sys.path.insert(0, str(Path(__file__).parent / "bin"))

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


class ComparisonOp(Enum):
    """Comparison operators"""
    EQ = "=="
    NEQ = "!="
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="
    LIKE = "LIKE"
    NOT_LIKE = "NOT LIKE"
    IN = "IN"
    NOT_IN = "NOT IN"


class LogQuery:
    """Splunk-like query builder"""

    def __init__(self):
        self.filters: List[Callable] = []
        self.sourcetype_filter: Optional[str] = None
        self.fields_to_display: List[str] = []
        self.limit_value: int = 100
        self.sort_field: Optional[str] = None
        self.sort_desc: bool = True

    def sourcetype(self, st: str) -> "LogQuery":
        """Filter by sourcetype"""
        self.sourcetype_filter = st
        return self

    def where(self, field: str, op: str, value: Any) -> "LogQuery":
        """Add where clause (e.g., where('severity', '==', 'critical'))"""
        def filter_func(event):
            field_value = self._get_field_value(event, field)
            if field_value is None:
                return False

            if op == "==":
                return field_value == value
            elif op == "!=":
                return field_value != value
            elif op == ">":
                return float(field_value) > float(value)
            elif op == ">=":
                return float(field_value) >= float(value)
            elif op == "<":
                return float(field_value) < float(value)
            elif op == "<=":
                return float(field_value) <= float(value)
            elif op == "LIKE":
                return re.search(value, str(field_value), re.IGNORECASE)
            elif op == "NOT LIKE":
                return not re.search(value, str(field_value), re.IGNORECASE)
            elif op == "IN":
                return field_value in value if isinstance(value, list) else field_value == value
            elif op == "NOT IN":
                return field_value not in value if isinstance(value, list) else field_value != value
            return True

        self.filters.append(filter_func)
        return self

    def fields(self, *fields: str) -> "LogQuery":
        """Select specific fields to display"""
        self.fields_to_display = list(fields)
        return self

    def limit(self, count: int) -> "LogQuery":
        """Limit results"""
        self.limit_value = count
        return self

    def sort(self, field: str, desc: bool = True) -> "LogQuery":
        """Sort results"""
        self.sort_field = field
        self.sort_desc = desc
        return self

    def _get_field_value(self, event: Dict[str, Any], field: str) -> Any:
        """Get field value from event (supports nested fields with dot notation)"""
        parts = field.split(".")
        value = event
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    def execute(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute query on events"""
        results = events

        # Filter by sourcetype
        if self.sourcetype_filter:
            results = [e for e in results if e.get("sourcetype") == self.sourcetype_filter]

        # Apply where filters
        for filter_func in self.filters:
            results = [e for e in results if filter_func(e)]

        # Sort
        if self.sort_field:
            results.sort(
                key=lambda e: self._get_field_value(e, self.sort_field) or "",
                reverse=self.sort_desc
            )

        # Limit
        results = results[:self.limit_value]

        # Select fields
        if self.fields_to_display:
            results = [
                {f: self._get_field_value(e, f) for f in self.fields_to_display if self._get_field_value(e, f) is not None}
                for e in results
            ]

        return results


class SplunkLogExplorer:
    """Interactive Splunk log explorer"""

    def __init__(self, events: List[Dict[str, Any]]):
        self.events = events
        self.sourcetypes = list(set(e.get("sourcetype") for e in events if "sourcetype" in e))

    def print_header(self):
        """Print explorer header"""
        print("\n" + "=" * 80)
        print("🔍 SPLUNK LOG EXPLORER - Local Query Tool")
        print("=" * 80)
        print(f"Total Events: {len(self.events)}")
        print(f"Sourcetypes: {', '.join(self.sourcetypes)}")
        print("\nAvailable Commands:")
        print("  query()          - Create new query")
        print("  show_tables()    - Show data summary")
        print("  show_sourcetypes() - Show available sourcetypes")
        print("  show_fields()    - Show all available fields")
        print("=" * 80 + "\n")

    def show_sourcetypes(self):
        """Show available sourcetypes"""
        print("\n📊 Available Sourcetypes:")
        for st in self.sourcetypes:
            count = len([e for e in self.events if e.get("sourcetype") == st])
            print(f"  • {st} ({count} events)")

    def show_fields(self):
        """Show all available fields"""
        all_fields = set()
        for event in self.events:
            all_fields.update(event.keys())

        print("\n📋 Available Fields:")
        for field in sorted(all_fields):
            print(f"  • {field}")

    def show_tables(self):
        """Show data summary"""
        print("\n📈 Data Summary by Sourcetype:")
        for st in self.sourcetypes:
            events = [e for e in self.events if e.get("sourcetype") == st]
            if events:
                print(f"\n{st}:")
                print(f"  Count: {len(events)}")

                # Show sample event
                sample = events[0]
                print(f"  Sample event:")
                for key, value in sorted(sample.items())[:5]:
                    val_str = str(value)[:60]
                    print(f"    {key}: {val_str}")

    def query(self) -> LogQuery:
        """Create new query"""
        return LogQuery()

    def run_example_queries(self):
        """Run example queries"""
        print("\n" + "=" * 80)
        print("📚 EXAMPLE QUERIES")
        print("=" * 80)

        # Example 1: Critical vulnerabilities
        print("\n[1] Critical Vulnerabilities:")
        print("Query: query().sourcetype('faze:vulnerability').where('severity', '==', 'critical')")
        q = self.query().sourcetype("faze:vulnerability").where("severity", "==", "critical")
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")
        if results:
            self._print_table(results[:3], ["vulnerability_id", "title", "severity", "cvss_score"])

        # Example 2: High-risk assets
        print("\n[2] Assets with Vulnerabilities:")
        print("Query: query().sourcetype('faze:asset').limit(5)")
        q = self.query().sourcetype("faze:asset").limit(5)
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")
        if results:
            self._print_table(results, ["asset_id", "name", "asset_type"])

        # Example 3: Network findings
        print("\n[3] Network Findings:")
        print("Query: query().sourcetype('faze:network')")
        q = self.query().sourcetype("faze:network")
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")

        # Example 4: Exposed credentials
        print("\n[4] Exposed Credentials:")
        print("Query: query().sourcetype('faze:credentials')")
        q = self.query().sourcetype("faze:credentials")
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")

        # Example 5: Misconfigurations
        print("\n[5] Misconfigurations:")
        print("Query: query().sourcetype('faze:misconfiguration')")
        q = self.query().sourcetype("faze:misconfiguration")
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")

        # Example 6: Custom filter - CVSS >= 7
        print("\n[6] High CVSS Score Vulnerabilities (>=7):")
        print("Query: query().sourcetype('faze:vulnerability').where('cvss_score', '>=', 7)")
        q = self.query().sourcetype("faze:vulnerability").where("cvss_score", ">=", 7)
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")
        if results:
            self._print_table(results[:3], ["title", "cvss_score", "severity"])

        # Example 7: Compliance findings
        print("\n[7] Compliance Findings:")
        print("Query: query().sourcetype('faze:compliance')")
        q = self.query().sourcetype("faze:compliance")
        results = q.execute(self.events)
        print(f"Results: {len(results)} events")

    def _print_table(self, results: List[Dict], fields: List[str]):
        """Print results as table"""
        if not results:
            return

        # Calculate column widths
        widths = {f: len(f) for f in fields}
        for result in results:
            for field in fields:
                val = result.get(field, "")
                widths[field] = max(widths[field], len(str(val)[:40]))

        # Print header
        header = " | ".join(f.ljust(widths[f]) for f in fields)
        print("  " + header)
        print("  " + "-" * len(header))

        # Print rows
        for result in results:
            row = " | ".join(str(result.get(f, "")).ljust(widths[f])[:40] for f in fields)
            print("  " + row)


def load_logs_from_addon() -> List[Dict[str, Any]]:
    """Load logs from FAZE addon"""
    try:
        from faze_comprehensive_addon import FAZEComprehensiveAddon

        addon = FAZEComprehensiveAddon()
        addon.fetch_all_data()

        events = []
        for sourcetype_events in addon.events_by_sourcetype.values():
            events.extend(sourcetype_events)

        # Add audit logs
        for audit_entry in addon.audit_log:
            event = {
                "timestamp": audit_entry["timestamp"],
                "sourcetype": "faze:audit",
                "source": "faze_addon",
                **audit_entry
            }
            events.append(event)

        return events
    except Exception as e:
        print(f"Error loading logs: {e}", file=sys.stderr)
        return []


def main():
    """Main entry point"""
    print("Loading FAZE logs...")
    events = load_logs_from_addon()

    if not events:
        print("No events loaded. Check FAZE_API_KEY environment variable.")
        sys.exit(1)

    explorer = SplunkLogExplorer(events)
    explorer.print_header()
    explorer.show_sourcetypes()
    explorer.show_fields()
    explorer.run_example_queries()

    print("\n" + "=" * 80)
    print("💡 Use Python interactive shell to create custom queries:")
    print("=" * 80)
    print("""
explorer = SplunkLogExplorer(events)

# Query critical vulnerabilities
q = explorer.query().sourcetype('faze:vulnerability').where('severity', '==', 'critical')
results = q.execute(events)

# Query by CVSS score
q = explorer.query().where('cvss_score', '>', 8).sort('cvss_score', desc=True)
results = q.execute(events)

# Multiple conditions
q = explorer.query().sourcetype('faze:vulnerability').where('severity', '==', 'high').limit(10)
results = q.execute(events)

# Print results
for result in results:
    print(json.dumps(result, indent=2))
""")


if __name__ == "__main__":
    main()
