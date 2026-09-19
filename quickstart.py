"""
Quick Reference Guide - Enterprise Security Test Suite
Run this to see available commands and examples
"""

QUICK_START = """
==============================================================
  Sentinel-12 Security Protocol - Quick Reference
==============================================================

WARNING: MUST ONLY BE TESTED ON YOUR OWN DOMAIN, YOUR OWN APPLICATION,
OR TARGETS WHERE YOU HAVE WRITTEN PERMISSION FOR SECURITY AUDITING.

SETUP (First Time)
──────────────────────────────────────────────────────────────
1. Copy configuration template:
   cp config.example.yaml config.yaml

2. Edit config.yaml with YOUR application URL and session cookies:
   - Login to YOUR application
   - Open DevTools (F12) -> Application -> Cookies
   - Copy session cookie value

3. Update config.yaml with your authorized target settings

BASIC USAGE (CLI)
──────────────────────────────────────────────────────────────
# Run all 12 security modules
python runner.py --config config.yaml

# Run specific modules
python runner.py --config config.yaml --modules iam rbac business_logic

# Generate HTML report
python runner.py --config config.yaml --output report.html --format html

# Verbose mode (detailed output)
python runner.py --config config.yaml --verbose

REACT WEB DASHBOARD (DEFCON 1 SITUATION ROOM)
──────────────────────────────────────────────────────────────
# Option A: Run production web dashboard server via Python
python web_server.py

# Option B: Build React frontend assets manually
cd frontend
npm install
npm run build

# Option C: Run React development server
cd frontend
npm run dev

AVAILABLE MODULES (12 SECTORS)
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

MORE INFO
──────────────────────────────────────────────────────────────
Full documentation: README.md
Contribution guide: CONTRIBUTING.md
Security policy: SECURITY.md
"""

if __name__ == '__main__':
    print(QUICK_START)
