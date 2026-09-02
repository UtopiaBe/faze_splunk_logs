#!/usr/bin/env python3
"""
Test script for FAZE Security API integration
Tests connectivity and vulnerability fetching
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    print("python-dotenv not installed. Install with: pip install python-dotenv")

# Add bin directory to path
sys.path.insert(0, str(Path(__file__).parent / "bin"))

from faze_security_addon import FAZESecurityAddon


class FAZEConnectionTester:
    """Test FAZE API connectivity and functionality"""

    def __init__(self):
        self.test_results = []
        self.api_key = os.getenv("FAZE_API_KEY")
        self.api_url = os.getenv("FAZE_API_URL", "https://api.faze.security")

    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """Log test result"""
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")
        if message:
            print(f"       {message}")
        self.test_results.append({"test": test_name, "passed": passed, "message": message})

    def test_environment_setup(self) -> bool:
        """Test 1: Check environment variables are set"""
        print("\n[1] Environment Setup")
        print("-" * 50)

        # Check API key
        if self.api_key:
            self.log_test(
                "FAZE_API_KEY set",
                True,
                f"Key length: {len(self.api_key)} chars"
            )
        else:
            self.log_test(
                "FAZE_API_KEY set",
                False,
                "Environment variable FAZE_API_KEY not found. Set it with: export FAZE_API_KEY='your_key'"
            )
            return False

        # Check API URL
        self.log_test(
            "FAZE_API_URL configured",
            True,
            f"URL: {self.api_url}"
        )

        return True

    def test_addon_initialization(self) -> Optional[FAZESecurityAddon]:
        """Test 2: Initialize addon"""
        print("\n[2] Addon Initialization")
        print("-" * 50)

        try:
            addon = FAZESecurityAddon(self.api_key)
            self.log_test(
                "FAZESecurityAddon initialized",
                True,
                "Successfully created addon instance"
            )
            return addon
        except Exception as e:
            self.log_test(
                "FAZESecurityAddon initialized",
                False,
                str(e)
            )
            return None

    def test_api_connectivity(self, addon: FAZESecurityAddon) -> bool:
        """Test 3: Test API connectivity"""
        print("\n[3] API Connectivity")
        print("-" * 50)

        try:
            assets = addon.get_assets()
            if assets is not None:
                self.log_test(
                    "API connectivity",
                    True,
                    f"Successfully connected to FAZE API"
                )
                return True
            else:
                self.log_test(
                    "API connectivity",
                    False,
                    "Got null response from API"
                )
                return False
        except Exception as e:
            self.log_test(
                "API connectivity",
                False,
                str(e)
            )
            return False

    def test_asset_fetching(self, addon: FAZESecurityAddon) -> bool:
        """Test 4: Fetch assets"""
        print("\n[4] Asset Fetching")
        print("-" * 50)

        try:
            assets = addon.get_assets()

            if isinstance(assets, list):
                self.log_test(
                    "Asset fetching",
                    True,
                    f"Found {len(assets)} asset(s)"
                )

                if assets:
                    print("\n  Assets in FAZE:")
                    for asset in assets[:5]:  # Show first 5
                        asset_id = asset.get("id") or asset.get("asset_id", "unknown")
                        asset_name = asset.get("name") or asset.get("asset_name", "unknown")
                        print(f"    - {asset_name} (ID: {asset_id})")
                    if len(assets) > 5:
                        print(f"    ... and {len(assets) - 5} more")

                return len(assets) > 0
            else:
                self.log_test(
                    "Asset fetching",
                    False,
                    f"Unexpected response format: {type(assets)}"
                )
                return False

        except Exception as e:
            self.log_test(
                "Asset fetching",
                False,
                str(e)
            )
            return False

    def test_vulnerability_scanning(self, addon: FAZESecurityAddon) -> bool:
        """Test 5: Scan for vulnerabilities"""
        print("\n[5] Vulnerability Scanning")
        print("-" * 50)

        try:
            addon.fetch_and_index_vulnerabilities()

            total = len(addon.vulnerabilities)
            if total > 0:
                self.log_test(
                    "Vulnerability scanning",
                    True,
                    f"Found {total} vulnerability/vulnerabilities"
                )

                stats = addon.get_statistics()
                print(f"\n  Vulnerability Summary:")
                print(f"    Total: {stats.get('total_vulnerabilities', 0)}")
                print(f"    Average CVSS: {stats.get('average_cvss_score', 0)}")

                severity_count = stats.get("by_severity", {})
                if severity_count:
                    print(f"\n  By Severity:")
                    for severity in ["critical", "high", "medium", "low", "info"]:
                        count = severity_count.get(severity, 0)
                        if count > 0:
                            print(f"    {severity.upper()}: {count}")

                return True
            else:
                self.log_test(
                    "Vulnerability scanning",
                    False,
                    "No vulnerabilities found (check if assets have been scanned in FAZE)"
                )
                return False

        except Exception as e:
            self.log_test(
                "Vulnerability scanning",
                False,
                str(e)
            )
            return False

    def test_event_formatting(self, addon: FAZESecurityAddon) -> bool:
        """Test 6: Test Splunk event formatting"""
        print("\n[6] Event Formatting")
        print("-" * 50)

        try:
            if not addon.vulnerabilities:
                self.log_test(
                    "Event formatting",
                    False,
                    "No vulnerabilities to format"
                )
                return False

            events = addon.generate_splunk_events()

            if events:
                self.log_test(
                    "Event formatting",
                    True,
                    f"Successfully formatted {len(events)} Splunk event(s)"
                )

                # Show sample event
                if events:
                    print(f"\n  Sample Event (first 200 chars):")
                    print(f"    {events[0][:200]}...")

                return True
            else:
                self.log_test(
                    "Event formatting",
                    False,
                    "No events generated"
                )
                return False

        except Exception as e:
            self.log_test(
                "Event formatting",
                False,
                str(e)
            )
            return False

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)

        passed = sum(1 for r in self.test_results if r["passed"])
        total = len(self.test_results)

        print(f"\nResults: {passed}/{total} tests passed")

        if passed == total:
            print("\n✓ All tests passed! Your FAZE integration is ready.")
            print("\nNext steps:")
            print("  1. Run: python3 bin/faze_security_addon.py")
            print("  2. Add to Splunk as a scripted input")
            print("  3. Search: source='faze_security_api'")
        else:
            print(f"\n✗ {total - passed} test(s) failed. See errors above.")

    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "=" * 50)
        print("FAZE SECURITY API - INTEGRATION TESTS")
        print("=" * 50)

        # Test 1: Environment
        if not self.test_environment_setup():
            self.print_summary()
            return

        # Test 2: Initialization
        addon = self.test_addon_initialization()
        if not addon:
            self.print_summary()
            return

        # Test 3: Connectivity
        if not self.test_api_connectivity(addon):
            self.print_summary()
            return

        # Test 4: Assets
        has_assets = self.test_asset_fetching(addon)

        if has_assets:
            # Test 5: Vulnerabilities
            self.test_vulnerability_scanning(addon)

            # Test 6: Formatting
            self.test_event_formatting(addon)

        # Print summary
        self.print_summary()


def main():
    """Main entry point"""
    tester = FAZEConnectionTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
