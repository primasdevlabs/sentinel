# Changelog

All notable changes to the Sentinel-12 Security Protocol ([primasdevlabs/sentinel](https://github.com/primasdevlabs/sentinel)) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-09-19

### Added
- **Open-Source Infrastructure**: Full GitHub open-source release under [primasdevlabs/sentinel](https://github.com/primasdevlabs/sentinel).
- **Comprehensive Documentation**: Complete setup guides, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and issue/PR templates.
- **12 Security Test Modules**:
  - `iam`: Identity, Authentication & Session Security.
  - `rbac`: Role-Based Access Control & Privilege Escalation.
  - `multitenancy`: Cross-tenant boundary isolation.
  - `business_logic`: Workflow state machine integrity.
  - `file_security`: Unrestricted file uploads and path traversal.
  - `api_security`: OWASP API Top 10 vulnerabilities.
  - `rate_limit`: Throttling and brute-force protection.
  - `crypto`: Secrets management and encryption validation.
  - `audit`: Logging integrity and log injection defense.
  - `supply_chain`: Dependency vulnerability scanning.
  - `infrastructure`: Debug mode and exposed sensitive asset checks.
  - `human_process`: Operational process security checks.
- **Reporting Engine**:
  - JSON schema export for automated CI/CD pipeline integration.
  - Interactive HTML report dashboard with severity filtering and findings summary.
- **Risk Score Calculator**: Automated calculation of weighted security risk scores.

### Changed
- Standardized command line interface with module filtering (`--modules`).
- Cleaned README documentation to professional, emoji-free markdown standards.

---

## [1.0.0] - Initial Prototype

### Added
- Initial core runner and base security test class implementation.
