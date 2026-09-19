"""
Sentinel-12 SDK Quickstart Example
Demonstrates how to use the Sentinel Python SDK programmatically
"""

import sys
import os

# Include parent directory to import sentinel_sdk locally
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel_sdk import SentinelClient, SecurityAssertionError, Severity


def main():
    print("=" * 60)
    print("SENTINEL-12 PYTHON SDK DEMO")
    print("=" * 60)

    # Initialize SDK Client
    client = SentinelClient(base_url="http://127.0.0.1:8000", verbose=True)

    # Configure session cookies for role testing
    client.set_session("admin", "admin_cookie_token_sample")
    client.set_session("user_a", "user_a_cookie_token_sample")

    print("\nExecuting selected security domain probes...")
    # Execute specific security modules
    findings = client.run_modules(["iam", "rbac", "business_logic"])

    print(f"\nExecution Complete. Total Findings Logged: {len(findings)}")

    # Filter findings by severity
    criticals = client.get_findings(Severity.CRITICAL)
    print(f"Critical Findings: {len(criticals)}")

    # Compute risk score
    risk_score = client.calculate_risk_score()
    print(f"Calculated Risk Score: {risk_score}")

    # Export reports
    client.export_json("sdk_report.json")
    client.export_html("sdk_report.html")

    # Assert security standards (CI/CD Pipeline assertion)
    try:
        print("\nVerifying CI/CD Security Assertions...")
        client.assert_no_critical_vulnerabilities()
        print("[SUCCESS] Security assertion passed: No CRITICAL issues found.")
    except SecurityAssertionError as e:
        print(f"[ASSERTION FAILED]\n{e}")

if __name__ == '__main__':
    main()
