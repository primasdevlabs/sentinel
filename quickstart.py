"""
Quick Reference Guide - Enterprise Security Test Suite
Run this to see available commands and examples
"""

QUICK_START = """
╔══════════════════════════════════════════════════════════════╗
║   Sentinel-12 Security Protocol - Quick Reference          ║
╚══════════════════════════════════════════════════════════════╝

📋 SETUP (First Time)
──────────────────────────────────────────────────────────────
1. Copy configuration template:
   cp pentest/config.example.yaml pentest/config.yaml

2. Edit config.yaml and add your session cookies:
   - Login to the app
   - Open DevTools (F12) → Application → Cookies
   - Copy 'laravel_session' cookie value

3. Update config.yaml with your sessions

🚀 BASIC USAGE
──────────────────────────────────────────────────────────────
# Run all tests
python -m pentest.runner --config pentest/config.yaml

# Run specific modules
python -m pentest.runner --config pentest/config.yaml --modules iam rbac

# Generate HTML report
python -m pentest.runner --config pentest/config.yaml \\
  --output report.html --format html

# Verbose mode (detailed output)
python -m pentest.runner --config pentest/config.yaml --verbose

📦 AVAILABLE MODULES
──────────────────────────────────────────────────────────────
iam              - Identity, Auth & Session Security
rbac             - Authorization & RBAC Integrity
multitenancy     - Multi-Tenancy & Data Isolation
business_logic   - Business Logic & Workflow Integrity
file_security    - File & Document Security
api_security     - API Security (OWASP API Top 10)
rate_limit       - Rate Limiting & Abuse Controls
crypto           - Cryptography & Secrets Management
audit            - Logging, Audit & Forensics
supply_chain     - Supply Chain & Dependency Risk
infrastructure   - Infrastructure & Deployment Security
human_process    - Human-Driven & Process Attacks

🎯 COMMON SCENARIOS
──────────────────────────────────────────────────────────────
# Quick security check (critical modules only)
python -m pentest.runner --config pentest/config.yaml \\
  --modules iam rbac multitenancy business_logic

# Full audit with HTML report
python -m pentest.runner --config pentest/config.yaml \\
  --output security-audit-$(date +%Y%m%d).html \\
  --format html

# API-focused testing
python -m pentest.runner --config pentest/config.yaml \\
  --modules api_security rate_limit file_security

# Infrastructure audit
python -m pentest.runner --config pentest/config.yaml \\
  --modules infrastructure supply_chain crypto

📊 UNDERSTANDING RESULTS
──────────────────────────────────────────────────────────────
🔥 CRITICAL  - Immediate action required (auth bypass, data exposure)
🚨 HIGH      - Urgent attention needed (privilege escalation)
⚠️  MEDIUM   - Should be addressed (missing rate limits)
ℹ️  LOW      - Minor issues (sequential IDs)
💡 INFO      - Informational (manual verification needed)
✅ PASSED    - Security control working correctly

Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)

⚠️  WARNINGS
──────────────────────────────────────────────────────────────
❌ NEVER run against production without authorization
❌ Tests may trigger security alerts
❌ Some tests may temporarily lock accounts
✅ Always use dedicated test accounts
✅ Run in staging/test environment only

📚 MORE INFO
──────────────────────────────────────────────────────────────
Full documentation: pentest/README.md
Configuration help: pentest/config.example.yaml
"""

if __name__ == '__main__':
    print(QUICK_START)
