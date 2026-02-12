# Sentinel-12 Security Protocol

A comprehensive, modular penetration testing suite covering 12 critical enterprise security domains.

## 🎯 Features

- **12 Security Domains**: IAM, RBAC, Multi-Tenancy, Business Logic, File Security, API Security, Rate Limiting, Cryptography, Audit, Supply Chain, Infrastructure, and Human Process
- **Modular Architecture**: Run all tests or specific modules
- **Multiple Report Formats**: JSON and HTML reports
- **Configurable**: YAML/JSON configuration support

## 📋 Security Domains Covered

1. **IAM (Identity, Auth & Session)**: Authentication, session management, CSRF, MFA
2. **RBAC (Authorization)**: Permission enforcement, privilege escalation, horizontal access
3. **Multi-Tenancy**: Tenant isolation, data scoping, cross-tenant access
4. **Business Logic**: Workflow integrity, state machines, race conditions
5. **File Security**: Upload validation, MIME handling, path traversal
6. **API Security**: OWASP API Top 10, over-fetching, mass enumeration
7. **Rate Limiting**: Throttling, abuse controls, lockout mechanisms
8. **Cryptography**: Password hashing, token security, JWT validation
9. **Audit & Logging**: Security events, log injection, forensics
10. **Supply Chain**: Dependency vulnerabilities, abandoned packages
11. **Infrastructure**: Debug mode, sensitive files, test routes
12. **Human Process**: Default credentials, over-permissioned roles

## 🚀 Quick Start

### 1. Setup

```bash
# Install dependencies (if needed)
pip install requests pyyaml

# Copy configuration template
cp pentest/config.example.yaml pentest/config.yaml
```

### 2. Configure

Edit `pentest/config.yaml` with your session cookies:

```yaml
base_url: "http://127.0.0.1:8000"
admin_session: "your_admin_session_cookie"
user_a_session: "your_user_a_session_cookie"
# ... etc
```

**To get session cookies:**
1. Login to the application
2. Open browser DevTools (F12)
3. Go to Application/Storage > Cookies
4. Copy the `laravel_session` cookie value

### 3. Run Tests

```bash
# Run all tests
python -m pentest.runner --config pentest/config.yaml

# Run specific modules
python -m pentest.runner --config pentest/config.yaml --modules iam rbac

# Generate HTML report
python -m pentest.runner --config pentest/config.yaml --output report.html --format html

# Verbose output
python -m pentest.runner --config pentest/config.yaml --verbose
```

## 📊 Available Modules

- `iam` - Identity, Authentication & Session Security
- `rbac` - Authorization & RBAC Integrity
- `multitenancy` - Multi-Tenancy & Data Isolation
- `business_logic` - Business Logic & Workflow Integrity
- `file_security` - File & Document Security
- `api_security` - API Security (OWASP API Top 10)
- `rate_limit` - Rate Limiting & Abuse Controls
- `crypto` - Cryptography & Secrets Management
- `audit` - Logging, Audit & Forensics
- `supply_chain` - Supply Chain & Dependency Risk
- `infrastructure` - Infrastructure & Deployment Security
- `human_process` - Human-Driven & Process Attacks

## 📈 Understanding Results

### Severity Levels

- 🔥 **CRITICAL**: Immediate action required (e.g., authentication bypass, data exposure)
- 🚨 **HIGH**: Urgent attention needed (e.g., privilege escalation, MIME spoofing)
- ⚠️ **MEDIUM**: Should be addressed (e.g., missing rate limits, weak validation)
- ℹ️ **LOW**: Minor issues (e.g., sequential IDs, verbose errors)
- 💡 **INFO**: Informational findings (e.g., manual verification required)
- ✅ **PASSED**: Security control working correctly

### Risk Score

The suite calculates a risk score based on findings:
- CRITICAL = 10 points
- HIGH = 5 points
- MEDIUM = 2 points
- LOW = 1 point

## ⚠️ Important Warnings

### Never Run Against Production Without Authorization

This suite simulates real attack patterns and may:
- Trigger security monitoring systems
- Generate security incident alerts
- Temporarily lock accounts or IP addresses
- Create audit log entries

### Required Sessions

For comprehensive testing, you need session cookies for:
- Admin user (full privileges)
- User A (standard user)
- User B (different standard user)
- Agency A user (for multi-tenancy)
- Agency B user (for multi-tenancy)

## 🔧 Advanced Usage

### Custom Configuration

```python
from pentest.runner import SecurityTestSuite

config = {
    'base_url': 'http://localhost:8000',
    'admin_session': 'your_session',
    'verbose': True
}

suite = SecurityTestSuite(config)
suite.run_all_tests(['iam', 'rbac'])
suite.export_json('report.json')
```

### Extending the Suite

Create custom test modules by extending `BaseSecurityTest`:

```python
from pentest.base_test import BaseSecurityTest, Severity

class CustomTests(BaseSecurityTest):
    def run_tests(self):
        # Your custom tests here
        pass
```

## 📝 Report Formats

### JSON Report

```json
{
  "metadata": {
    "target": "http://127.0.0.1:8000",
    "start_time": "2026-02-10T03:00:00",
    "duration_seconds": 45.2
  },
  "findings": [...],
  "summary": {
    "critical": 2,
    "high": 5,
    ...
  }
}
```

### HTML Report

Interactive HTML report with:
- Summary dashboard
- Severity breakdown
- Detailed findings
- Timestamps and metadata

## 🛡️ Security Best Practices

1. **Run in isolated environment** (staging, dedicated test environment)
2. **Use dedicated test accounts** (not production users)
3. **Review findings carefully** (some may be false positives)
4. **Prioritize CRITICAL and HIGH** findings
5. **Document remediation** efforts
6. **Re-test after fixes** to verify

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 📄 License

Internal use only - Primas Dev Labs
