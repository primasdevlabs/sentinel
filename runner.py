"""
Sentinel-12 Security Protocole - Main Runner
Orchestrates all security test modules and generates comprehensive reports
"""

import sys
import json
import argparse
from datetime import datetime
from typing import Dict, List
import yaml

from pentest.base_test import Severity, Finding
from pentest.modules.iam_tests import IAMSecurityTests
from pentest.modules.rbac_tests import RBACSecurityTests
from pentest.modules.multitenancy_tests import MultiTenancyTests
from pentest.modules.business_logic_tests import BusinessLogicTests
from pentest.modules.file_security_tests import FileSecurityTests
from pentest.modules.api_security_tests import APISecurityTests
from pentest.modules.rate_limit_tests import RateLimitTests
from pentest.modules.crypto_tests import CryptoSecurityTests
from pentest.modules.audit_tests import AuditSecurityTests
from pentest.modules.supply_chain_tests import SupplyChainTests
from pentest.modules.infrastructure_tests import InfrastructureTests
from pentest.modules.human_process_tests import HumanProcessTests


class SecurityTestSuite:
    """Main security test suite orchestrator"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.all_findings: List[Finding] = []
        self.start_time = None
        self.end_time = None
        
        # Initialize all test modules
        self.modules = {
            'iam': IAMSecurityTests(config),
            'rbac': RBACSecurityTests(config),
            'multitenancy': MultiTenancyTests(config),
            'business_logic': BusinessLogicTests(config),
            'file_security': FileSecurityTests(config),
            'api_security': APISecurityTests(config),
            'rate_limit': RateLimitTests(config),
            'crypto': CryptoSecurityTests(config),
            'audit': AuditSecurityTests(config),
            'supply_chain': SupplyChainTests(config),
            'infrastructure': InfrastructureTests(config),
            'human_process': HumanProcessTests(config)
        }
    
    def run_all_tests(self, selected_modules: List[str] = None):
        """Run all or selected test modules"""
        self.start_time = datetime.now()
        
        print("\n" + "="*70)
        print("🔒 ENTERPRISE SECURITY TEST SUITE - AGENTCORE CRM")
        print("="*70)
        print(f"Target: {self.config['base_url']}")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        modules_to_run = selected_modules or list(self.modules.keys())
        
        for module_name in modules_to_run:
            if module_name not in self.modules:
                print(f"\n⚠️  Unknown module: {module_name}")
                continue
            
            module = self.modules[module_name]
            
            try:
                module.run_tests()
                self.all_findings.extend(module.get_findings())
            except Exception as e:
                print(f"\n❌ Error running {module_name}: {e}")
        
        self.end_time = datetime.now()
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        print("\n" + "="*70)
        print("📊 TEST SUMMARY")
        print("="*70)
        
        # Count findings by severity
        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in self.all_findings:
            severity_counts[finding.severity.value] += 1
        
        print(f"\n🔥 CRITICAL: {severity_counts['critical']}")
        print(f"🚨 HIGH:     {severity_counts['high']}")
        print(f"⚠️  MEDIUM:   {severity_counts['medium']}")
        print(f"ℹ️  LOW:      {severity_counts['low']}")
        print(f"💡 INFO:     {severity_counts['info']}")
        print(f"✅ PASSED:   {severity_counts['passed']}")
        
        print(f"\nTotal Findings: {len(self.all_findings)}")
        print(f"Duration: {duration:.2f} seconds")
        print("="*70)
        
        # Risk score
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 5 +
            severity_counts['medium'] * 2 +
            severity_counts['low'] * 1
        )
        
        print(f"\n🎯 RISK SCORE: {risk_score}")
        
        if severity_counts['critical'] > 0:
            print("⚠️  CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED")
        elif severity_counts['high'] > 0:
            print("⚠️  HIGH SEVERITY ISSUES FOUND - URGENT ATTENTION NEEDED")
        elif severity_counts['medium'] > 0:
            print("✓ No critical issues, but medium severity findings need attention")
        else:
            print("✓ No major security issues detected")
        
        print("="*70 + "\n")
    
    def export_json(self, filename: str):
        """Export findings to JSON"""
        report = {
            "metadata": {
                "target": self.config['base_url'],
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "duration_seconds": (self.end_time - self.start_time).total_seconds()
            },
            "findings": [f.to_dict() for f in self.all_findings],
            "summary": {
                severity.value: sum(1 for f in self.all_findings if f.severity == severity)
                for severity in Severity
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ JSON report exported to: {filename}")
    
    def export_html(self, filename: str):
        """Export findings to HTML"""
        import html as html_module
        
        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in self.all_findings:
            severity_counts[finding.severity.value] += 1
        
        duration = (self.end_time - self.start_time).total_seconds()

        # Compute overall risk score and status (to mirror console summary)
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 5 +
            severity_counts['medium'] * 2 +
            severity_counts['low'] * 1
        )

        if severity_counts['critical'] > 0:
            overall_status = "CRITICAL - Immediate action required"
            status_class = "status-critical"
        elif severity_counts['high'] > 0:
            overall_status = "HIGH - Urgent attention needed"
            status_class = "status-high"
        elif severity_counts['medium'] > 0:
            overall_status = "MEDIUM - Remediation recommended"
            status_class = "status-medium"
        else:
            overall_status = "LOW - No major security issues detected"
            status_class = "status-low"
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report - Sentinel-12 Security Protocol</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 0; background: #0f172a; color: #111827; }}
        .container {{ max-width: 1200px; margin: 40px auto; background: #ffffff; padding: 32px 40px; border-radius: 12px; box-shadow: 0 20px 40px rgba(15, 23, 42, 0.25); }}
        h1 {{ margin: 0; font-size: 28px; color: #0f172a; }}
        h2 {{ margin-top: 32px; font-size: 20px; color: #111827; }}

        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e5e7eb; padding-bottom: 16px; }}
        .subtitle {{ margin-top: 4px; color: #6b7280; font-size: 13px; }}
        .header-status {{ text-align: right; }}
        .header-status-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b7280; }}
        .header-score {{ font-size: 26px; font-weight: 700; color: #111827; margin-top: 4px; }}
        .status-chip {{ display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; margin-top: 6px; }}
        .status-critical {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
        .status-high {{ background: #fffbeb; color: #92400e; border: 1px solid #fed7aa; }}
        .status-medium {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
        .status-low {{ background: #ecfdf3; color: #166534; border: 1px solid #bbf7d0; }}

        .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 16px 18px; border-radius: 10px; text-align: center; color: #ffffff; }}
        .summary-card h3 {{ margin: 0 0 4px; font-size: 22px; }}
        .summary-card p {{ margin: 0; font-size: 13px; opacity: 0.9; }}
        .critical {{ background: #dc3545; color: white; }}
        .high {{ background: #fd7e14; color: white; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #17a2b8; color: white; }}
        .info {{ background: #6c757d; color: white; }}
        .passed {{ background: #28a745; color: white; }}

        .metadata {{ background: #f9fafb; padding: 16px 18px; border-radius: 10px; margin: 24px 0 12px; border: 1px solid #e5e7eb; font-size: 14px; }}
        .metadata-row {{ display: flex; flex-wrap: wrap; gap: 16px; margin: 4px 0; }}
        .metadata-label {{ font-weight: 600; color: #4b5563; margin-right: 4px; }}

        .severity-filter {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin: 12px 0 16px; font-size: 13px; color: #4b5563; }}
        .severity-filter button {{ border: 1px solid #e5e7eb; background: #ffffff; border-radius: 999px; padding: 4px 10px; font-size: 12px; cursor: pointer; color: #374151; display: inline-flex; align-items: center; gap: 4px; }}
        .severity-filter button.active {{ background: #111827; color: #f9fafb; border-color: #111827; }}

        .findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
        .findings-table thead tr {{ background: #f3f4f6; }}
        .findings-table th, .findings-table td {{ padding: 10px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; text-align: left; }}
        .findings-table th {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; }}

        .severity-badge {{ display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }}
        .severity-critical {{ background: #fef2f2; color: #b91c1c; }}
        .severity-high {{ background: #fffbeb; color: #92400e; }}
        .severity-medium {{ background: #eff6ff; color: #1d4ed8; }}
        .severity-low {{ background: #ecfdf3; color: #166534; }}
        .severity-info {{ background: #f3f4f6; color: #374151; }}
        .severity-passed {{ background: #ecfdf3; color: #15803d; }}

        details {{ margin-top: 4px; }}
        details summary {{ cursor: pointer; color: #2563eb; outline: none; }}
        details pre {{ margin-top: 6px; padding: 10px; background: #111827; color: #e5e7eb; border-radius: 8px; max-height: 260px; overflow: auto; font-size: 12px; }}

        .no-findings {{ padding: 16px; background: #ecfdf3; border-radius: 10px; border: 1px solid #bbf7d0; color: #166534; font-size: 14px; margin-top: 8px; }}

        @media (max-width: 768px) {{
            .container {{ margin: 16px; padding: 20px; }}
            .summary {{ grid-template-columns: repeat(2, 1fr); }}
            .header {{ flex-direction: column; gap: 12px; }}
            .header-status {{ align-self: flex-start; text-align: left; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🔒 Security Test Report</h1>
                <p class="subtitle">Sentinel-12 Security Protocol • AgentCore CRM</p>
            </div>
            <div class="header-status">
                <div class="header-status-label">Risk Score</div>
                <div class="header-score">{risk_score}</div>
                <div class="status-chip {status_class}">{overall_status}</div>
            </div>
        </div>
        
        <div class="metadata">
            <div class="metadata-row">
                <span class="metadata-label">Target:</span> <span>{target}</span>
            </div>
            <div class="metadata-row">
                <span class="metadata-label">Test Date:</span> <span>{test_date}</span>
            </div>
            <div class="metadata-row">
                <span class="metadata-label">Duration:</span> <span>{duration:.2f} seconds</span>
            </div>
            <div class="metadata-row">
                <span class="metadata-label">Total Findings:</span> <span>{total_findings}</span>
            </div>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>{critical_count}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{high_count}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{medium_count}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{low_count}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card info">
                <h3>{info_count}</h3>
                <p>Info</p>
            </div>
            <div class="summary-card passed">
                <h3>{passed_count}</h3>
                <p>Passed</p>
            </div>
        </div>
        
        <h2>Findings</h2>
        <div class="severity-filter">
            <span>Filter by severity:</span>
            <button data-severity="all" class="active">All</button>
            <button data-severity="critical">Critical ({critical_count})</button>
            <button data-severity="high">High ({high_count})</button>
            <button data-severity="medium">Medium ({medium_count})</button>
            <button data-severity="low">Low ({low_count})</button>
            <button data-severity="info">Info ({info_count})</button>
            <button data-severity="passed">Passed ({passed_count})</button>
        </div>

        <table class="findings-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
""".format(
            target=html_module.escape(self.config['base_url']),
            test_date=self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            duration=duration,
            total_findings=len(self.all_findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info'],
            passed_count=severity_counts['passed'],
            risk_score=risk_score,
            overall_status=overall_status,
            status_class=status_class
        )
        
        for finding in self.all_findings:
            details_html = ""
            if finding.details:
                details_html = (
                    "<details><summary>View details</summary>"
                    f"<pre>{html_module.escape(json.dumps(finding.details, indent=2))}</pre>"
                    "</details>"
                )
            
            html_content += """
                <tr class="finding-row" data-severity="{severity}">
                    <td>
                        <span class="severity-badge severity-{severity}">{severity_upper}</span>
                    </td>
                    <td>{message}</td>
                    <td>{details}</td>
                </tr>
""".format(
                severity=finding.severity.value,
                severity_upper=finding.severity.value.upper(),
                message=html_module.escape(finding.message),
                details=details_html
            )
        
        if not self.all_findings:
            html_content += """
                <tr>
                    <td colspan="3">
                        <div class="no-findings">
                            ✅ No security findings were reported by the executed test modules.
                        </div>
                    </td>
                </tr>
            """

        html_content += """
            </tbody>
        </table>

        <script>
            (function() {{
                const buttons = document.querySelectorAll('.severity-filter button');
                const rows = document.querySelectorAll('.findings-table tbody tr.finding-row');

                buttons.forEach((button) => {{
                    button.addEventListener('click', () => {{
                        const selected = button.getAttribute('data-severity');

                        buttons.forEach((b) => b.classList.remove('active'));
                        button.classList.add('active');

                        rows.forEach((row) => {{
                            const rowSeverity = row.getAttribute('data-severity');
                            if (selected === 'all' || !selected || rowSeverity === selected) {{
                                row.style.display = '';
                            }} else {{
                                row.style.display = 'none';
                            }}
                        }});
                    }});
                }});
            }})();
        </script>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML report exported to: {filename}")


def load_config(config_file: str = None) -> Dict:
    """Load configuration from file or use defaults"""
    if config_file:
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    # Default configuration
    return {
        'base_url': 'http://127.0.0.1:8000',
        'admin_session': None,
        'user_a_session': None,
        'user_b_session': None,
        'agency_a_session': None,
        'agency_b_session': None,
        'verbose': False
    }


def main():
    parser = argparse.ArgumentParser(
        description='Sentinel-12 Security Protocol'
    )
    parser.add_argument('--config', '-c', help='Configuration file (YAML or JSON)')
    parser.add_argument('--modules', '-m', nargs='+', 
                       help='Specific modules to run (default: all)')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['json', 'html'], 
                       default='json', help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    if args.verbose:
        config['verbose'] = True
    
    # Run tests
    suite = SecurityTestSuite(config)
    suite.run_all_tests(args.modules)
    
    # Export report
    if args.output:
        if args.format == 'json':
            suite.export_json(args.output)
        else:
            suite.export_html(args.output)


if __name__ == '__main__':
    main()
