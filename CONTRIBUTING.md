# Contributing to Sentinel-12 Security Protocol

Thank you for your interest in contributing to the Sentinel-12 Security Protocol repository at [primasdevlabs/sentinel](https://github.com/primasdevlabs/sentinel). 

Contributions from the security community help make Sentinel stronger, more modular, and more effective for everyone.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to the project maintainers.

---

## How Can I Contribute?

### 1. Reporting Bugs

Before creating a bug report, please check the [GitHub Issue Tracker](https://github.com/primasdevlabs/sentinel/issues) to ensure the issue hasn't already been reported.

When creating a bug report, please include:
- A clear, descriptive title.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Relevant command-line output or anonymized report logs.
- Python version, OS platform, and relevant package versions (`requests`, `pyyaml`).

### 2. Suggesting Enhancements & New Test Modules

Enhancement suggestions and proposals for new security test modules are tracked on [GitHub Issues](https://github.com/primasdevlabs/sentinel/issues).

When proposing a new test module:
- Clearly explain the security domain or OWASP risk category addressed.
- Outline the proposed attack vectors simulated.
- Describe required configuration options and expected findings.

### 3. Submitting Pull Requests

1. **Fork the Repository**: Create your own fork of [primasdevlabs/sentinel](https://github.com/primasdevlabs/sentinel).
2. **Clone Locally**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/sentinel.git
   cd sentinel
   ```
3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/my-new-module
   ```
4. **Implement Changes**:
   - Follow existing Python coding standards (PEP 8).
   - Ensure custom security modules inherit from `BaseSecurityTest`.
   - Ensure no hardcoded credentials or secrets are committed.
5. **Test Your Changes**:
   - Verify that your code executes cleanly with `python runner.py`.
   - Check JSON and HTML export functionality.
6. **Commit & Push**:
   ```bash
   git commit -m "feat(module): add custom security check for rate limits"
   git push origin feature/my-new-module
   ```
7. **Open a Pull Request**: Submit your pull request against the `main` branch of [primasdevlabs/sentinel](https://github.com/primasdevlabs/sentinel/pulls).

---

## Development Setup

### Environment Requirements

- Python 3.8 or higher
- Node.js (v18+) and npm
- Git

### Installing Dependencies & Building UI

```bash
# Install Python test dependencies
pip install -r requirements.txt

# Build the React UI Dashboard
cd frontend
npm install
npm run build
cd ..
```

### Running the Project

```bash
# CLI Test Runner
python runner.py --config config.yaml

# Web UI Server
python web_server.py
```

---

## Module Guidelines

When writing new test modules for `sentinel/modules/`:

1. Inherit from `BaseSecurityTest` (defined in `base_test.py`).
2. Implement the `run_tests()` method.
3. Log all findings using `self.log(Severity.<LEVEL>, "Message", details_dict)`.
4. Handle HTTP request exceptions gracefully to prevent suite crashes.
5. Keep requests configurable via `self.config`.

Example skeleton:

```python
from base_test import BaseSecurityTest, Severity

class CustomSecurityTests(BaseSecurityTest):
    def run_tests(self):
        response = self.request(self.sessions['unauthenticated'], 'GET', '/api/public')
        if response and response.status_code == 200:
            self.log(Severity.PASSED, "Public endpoint accessible")
        else:
            self.log(Severity.LOW, "Public endpoint unreachable")
```

---

## License & Attribution

By contributing to Sentinel-12 Security Protocol, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
