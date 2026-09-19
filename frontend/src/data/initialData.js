export const initialModules = [
  {
    id: 'iam',
    name: 'IAM & Authentication',
    code: 'iam',
    description: 'Identity verification, public vs protected access, session persistence, CSRF tokens, and MFA bypass checks.',
    owasp: 'A07:2021 Identification & Auth Failures',
    selected: true,
    totalChecks: 9
  },
  {
    id: 'rbac',
    name: 'Authorization & RBAC',
    code: 'rbac',
    description: 'Vertical/horizontal privilege escalation, bulk permission abuse, and API vs UI permission mismatch.',
    owasp: 'A01:2021 Broken Access Control',
    selected: true,
    totalChecks: 7
  },
  {
    id: 'multitenancy',
    name: 'Multi-Tenancy Isolation',
    code: 'multitenancy',
    description: 'Tenant ID payload tampering, foreign key scoping, search index leakage, and cross-tenant resource access.',
    owasp: 'API1:2023 Broken Object Level Auth',
    selected: true,
    totalChecks: 6
  },
  {
    id: 'business_logic',
    name: 'Business Logic Integrity',
    code: 'business_logic',
    description: 'Workflow status skipping, terminal state downgrades, race conditions, replay attacks, and numeric tampering.',
    owasp: 'API6:2023 Unrestricted Access to Business Flows',
    selected: true,
    totalChecks: 7
  },
  {
    id: 'file_security',
    name: 'File & Document Uploads',
    code: 'file_security',
    description: 'Unrestricted file upload, double extension bypass, MIME type spoofing, path traversal, and malicious SVG script execution.',
    owasp: 'A04:2021 Insecure Design',
    selected: true,
    totalChecks: 5
  },
  {
    id: 'api_security',
    name: 'API Security & OWASP Top 10',
    code: 'api_security',
    description: 'Mass assignment, excessive data exposure, endpoint enumeration, filter injection, and BOLA vulnerability checks.',
    owasp: 'OWASP API Security Top 10',
    selected: true,
    totalChecks: 8
  },
  {
    id: 'rate_limit',
    name: 'Rate Limiting & Abuse',
    code: 'rate_limit',
    description: 'Brute-force protection, endpoint request throttling, account lockout policy, and IP header bypass tests.',
    owasp: 'API4:2023 Unrestricted Resource Consumption',
    selected: true,
    totalChecks: 4
  },
  {
    id: 'crypto',
    name: 'Cryptography & Secrets',
    code: 'crypto',
    description: 'JWT signature verification, token entropy, password hashing algorithms, and sensitive data leakage in responses.',
    owasp: 'A02:2021 Cryptographic Failures',
    selected: true,
    totalChecks: 5
  },
  {
    id: 'audit',
    name: 'Logging & Audit Forensics',
    code: 'audit',
    description: 'Security event logging, audit trail tamper protection, log injection vulnerability, and timestamp validation.',
    owasp: 'A09:2021 Security Logging & Monitoring Failures',
    selected: true,
    totalChecks: 4
  },
  {
    id: 'supply_chain',
    name: 'Supply Chain Risk',
    code: 'supply_chain',
    description: 'Vulnerable third-party packages, abandoned dependencies, licenses compliance, and software bill of materials (SBOM).',
    owasp: 'A06:2021 Vulnerable & Outdated Components',
    selected: true,
    totalChecks: 4
  },
  {
    id: 'infrastructure',
    name: 'Infrastructure & Config',
    code: 'infrastructure',
    description: 'Debug mode detection, exposed sensitive configuration files (.env, git), test route leaks, and CORS header policy.',
    owasp: 'A05:2021 Security Misconfiguration',
    selected: true,
    totalChecks: 6
  },
  {
    id: 'human_process',
    name: 'Human & Operational Risk',
    code: 'human_process',
    description: 'Default credentials check, over-permissioned administrative roles, and social engineering entry points.',
    owasp: 'Operational Security',
    selected: true,
    totalChecks: 4
  }
];

export const initialConfig = {
  base_url: 'http://127.0.0.1:8000',
  admin_session: 'laravel_session_admin_secure_token_991823',
  user_a_session: 'laravel_session_user_a_token_44129',
  user_b_session: 'laravel_session_user_b_token_88712',
  agency_a_session: 'laravel_session_tenant_a_token_11203',
  agency_b_session: 'laravel_session_tenant_b_token_55941',
  verbose: true,
  request_timeout: 10,
  request_delay: 0.1,
  max_rate_limit_requests: 100
};

export const sampleFindings = [
  {
    id: 'f-1',
    severity: 'critical',
    module: 'business_logic',
    moduleName: 'Business Logic Integrity',
    message: 'Illegal workflow transition allowed: Order Lifecycle Pending -> Shipped (skipping payment verification)',
    details: {
      endpoint: '/api/v1/orders/test-uuid',
      method: 'PATCH',
      payload: { status: 'shipped' },
      status_code: 200,
      cwe: 'CWE-840: Business Logic Errors',
      recommendation: 'Enforce server-side state machine transition checks prior to updating resource state.'
    },
    timestamp: '2026-09-19 12:10:05'
  },
  {
    id: 'f-2',
    severity: 'critical',
    module: 'multitenancy',
    moduleName: 'Multi-Tenancy Isolation',
    message: 'Cross-tenant access violation: Tenant B accessed Tenant A private invoice resource',
    details: {
      endpoint: '/api/v1/invoices/inv-tenant-a-992',
      method: 'GET',
      session_used: 'Tenant B',
      status_code: 200,
      cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
      recommendation: 'Enforce strict scoping on all relational ORM queries using session tenant context.'
    },
    timestamp: '2026-09-19 12:10:12'
  },
  {
    id: 'f-3',
    severity: 'high',
    module: 'rbac',
    moduleName: 'Authorization & RBAC',
    message: 'User A modified User B profile data via API (Horizontal Access Violation)',
    details: {
      endpoint: '/api/v1/users/user-b-uuid',
      method: 'PATCH',
      payload: { name: 'Hacked' },
      status_code: 200,
      cwe: 'CWE-285: Improper Authorization',
      recommendation: 'Implement policy-based access control checking resource ownership.'
    },
    timestamp: '2026-09-19 12:10:20'
  },
  {
    id: 'f-4',
    severity: 'high',
    module: 'crypto',
    moduleName: 'Cryptography & Secrets',
    message: 'JWT Token verification accepts "none" algorithm signature',
    details: {
      endpoint: '/api/v1/auth/token-verify',
      method: 'POST',
      header: { alg: 'none' },
      status_code: 200,
      cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
      recommendation: 'Reject tokens signed with "none" algorithm and enforce explicit HMAC/RSA algorithm checks.'
    },
    timestamp: '2026-09-19 12:10:28'
  },
  {
    id: 'f-5',
    severity: 'medium',
    module: 'rate_limit',
    moduleName: 'Rate Limiting & Abuse',
    message: 'Authentication login endpoint lacks rate limiting throttle policy',
    details: {
      endpoint: '/api/v1/auth/login',
      requests_sent: 50,
      successful_responses: 50,
      cwe: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
      recommendation: 'Configure middleware rate limit throttling (e.g. 5 requests per minute per IP).'
    },
    timestamp: '2026-09-19 12:10:35'
  },
  {
    id: 'f-6',
    severity: 'low',
    module: 'api_security',
    moduleName: 'API Security',
    message: 'Sequential ID enumeration possible on user endpoint',
    details: {
      endpoint: '/api/v1/users/1',
      note: 'Sequential auto-incrementing integer IDs exposed in API response.',
      cwe: 'CWE-340: Generation of Predictable Numbers or Identifiers',
      recommendation: 'Replace sequential database IDs with universally unique identifiers (UUIDv4).'
    },
    timestamp: '2026-09-19 12:10:40'
  },
  {
    id: 'f-7',
    severity: 'passed',
    module: 'iam',
    moduleName: 'IAM & Authentication',
    message: 'Public access to protected administrative route properly blocked (403 Forbidden)',
    details: {
      endpoint: '/admin/settings',
      status_code: 403
    },
    timestamp: '2026-09-19 12:10:45'
  },
  {
    id: 'f-8',
    severity: 'passed',
    module: 'iam',
    moduleName: 'IAM & Authentication',
    message: 'CSRF protection verified active for state-changing POST requests',
    details: {
      status_code: 419
    },
    timestamp: '2026-09-19 12:10:50'
  }
];
