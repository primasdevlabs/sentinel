"""
Module 1: Identity, Authentication & Session Security (IAM)
Tests authentication mechanisms, session management, and identity controls
"""

try:
    from base_test import BaseSecurityTest, Severity
except ImportError:
    from sentinel.base_test import BaseSecurityTest, Severity
import time
import uuid


class IAMSecurityTests(BaseSecurityTest):
    """
    Identity, Authentication & Session Security (IAM) Test Suite
    
    Evaluates authentication barriers, session management standards, CSRF protections, 
    and multi-factor authentication (MFA) controls against generic enterprise security guidelines.
    """
    
    def run_tests(self):
        """Orchestrate and execute all IAM security tests"""
        print("\n" + "="*60)
        print("MODULE 1: IDENTITY, AUTH & SESSION SECURITY (IAM)")
        print("="*60)
        
        self.test_public_vs_protected_access()
        self.test_session_persistence()
        self.test_csrf_protection()
        self.test_token_invalidation_after_logout()
        self.test_concurrent_session_limits()
        self.test_session_fixation()
        self.test_device_ip_change_behavior()
        self.test_password_reset_token_reuse()
        self.test_mfa_bypass_resistance()
    
    def test_public_vs_protected_access(self):
        """
        Test Public vs Protected Endpoint Access
        
        Verifies that restricted routes (dashboards, admin settings, user management, 
        and sensitive API routes) cannot be accessed without valid session credentials.
        """
        print("\n[TEST] Public vs Protected Endpoint Access")
        
        # Generic multi-domain enterprise protected routes
        protected_paths = [
            "/dashboard",
            "/admin/settings",
            "/api/v1/users",
            "/api/v1/roles/permissions",
            "/api/v1/notifications/recent",
            "/api/v1/orders",
            "/api/v1/profile",
            "/api/v1/analytics"
        ]
        
        session = self.sessions['unauthenticated']
        
        for path in protected_paths:
            r = self.request(session, "GET", path, allow_redirects=False)
            
            if not r:
                continue
                
            if r.status_code == 200:
                self.log(Severity.CRITICAL, 
                        f"Unauthenticated public access allowed to protected endpoint: {path}",
                        {"status_code": r.status_code, "path": path})
            elif r.status_code in (301, 302):
                location = r.headers.get("Location", "")
                if "login" in location.lower() or "auth" in location.lower():
                    self.log(Severity.PASSED, f"Properly redirected unauthenticated request to login: {path}")
                else:
                    self.log(Severity.MEDIUM,
                            f"Redirected unauthenticated request, but not to login page: {path}",
                            {"location": location})
            elif r.status_code == 401:
                self.log(Severity.PASSED, f"Unauthorized (401) returned as expected: {path}")
            elif r.status_code == 403:
                self.log(Severity.PASSED, f"Forbidden (403) returned as expected: {path}")
            else:
                self.log(Severity.LOW,
                        f"Unexpected HTTP status code for protected path: {path}",
                        {"status_code": r.status_code})
    
    def test_session_persistence(self):
        """
        Test Active Session Validation & Persistence
        
        Verifies that valid user sessions are properly recognized by the application server.
        """
        print("\n[TEST] Session Persistence & Validation")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test that valid active session is accepted
        r = self.request(self.sessions['user_a'], "GET", "/dashboard")
        
        if r and r.status_code == 200:
            self.log(Severity.PASSED, "Valid active user session successfully accepted")
        else:
            self.log(Severity.HIGH, 
                    "Valid user session was rejected by the server",
                    {"status_code": r.status_code if r else "None"})
    
    def test_csrf_protection(self):
        """
        Test Cross-Site Request Forgery (CSRF) Protection
        
        Verifies that state-changing HTTP POST/PUT/DELETE requests lacking a valid 
        CSRF token are rejected by the server.
        """
        print("\n[TEST] CSRF Protection Enforcement")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Attempt state-changing request without CSRF token
        session = self.sessions['user_a']
        original_tokens = self.csrf_tokens.copy()
        self.csrf_tokens.clear()  # Temporarily remove CSRF tokens
        
        r = session.post(
            f"{self.base_url}/api/v1/test-endpoint",
            headers={'Accept': 'application/json'},
            json={"test": "data"}
        )
        
        self.csrf_tokens = original_tokens  # Restore original tokens
        
        if r and r.status_code in (419, 403):
            self.log(Severity.PASSED, "CSRF protection active (419 Token Mismatch / 403 Forbidden)")
        elif r and r.status_code == 404:
            self.log(Severity.INFO, "Test endpoint not found (expected)")
        else:
            self.log(Severity.MEDIUM,
                    "CSRF protection status inconclusive without anti-CSRF token",
                    {"status_code": r.status_code if r else "None"})
    
    def test_token_invalidation_after_logout(self):
        """Test that session tokens are invalidated server-side upon user logout"""
        print("\n[TEST] Token Invalidation After Logout")
        self.log(Severity.INFO, 
                "Token invalidation test requires dedicated automated logout flow")
        self.log(Severity.INFO, 
                "Manual verification: Login -> Capture session cookie -> Logout -> Re-issue request with old cookie")
    
    def test_concurrent_session_limits(self):
        """Test concurrent session limits and session revocation policies"""
        print("\n[TEST] Concurrent Session Limits")
        self.log(Severity.INFO,
                "Concurrent session test requires multi-session credentials for the same user account")
        self.log(Severity.INFO,
                "Manual verification: Login from 2+ devices -> Verify if older session is invalidated")
    
    def test_session_fixation(self):
        """Test resistance to session fixation attacks by verifying session ID regeneration upon login"""
        print("\n[TEST] Session Fixation Resistance")
        
        session = self.sessions['unauthenticated']
        fixed_session_id = str(uuid.uuid4())
        session.cookies.set('laravel_session', fixed_session_id)
        
        self.log(Severity.INFO,
                "Session fixation test requires automated authentication flow")
        self.log(Severity.INFO,
                "Manual verification: Set pre-login session cookie -> Authenticate -> Verify session ID is regenerated")
    
    def test_device_ip_change_behavior(self):
        """Test session handling policies when client IP address or User-Agent changes mid-session"""
        print("\n[TEST] Device / IP Change Behavior")
        self.log(Severity.INFO,
                "Device/IP change test requires network proxy manipulation")
        self.log(Severity.INFO,
                "Manual verification: Login -> Change client IP/User-Agent -> Verify re-authentication requirement")
    
    def test_password_reset_token_reuse(self):
        """Test single-use enforcement on password reset tokens"""
        print("\n[TEST] Password Reset Token Reuse")
        self.log(Severity.INFO,
                "Password reset token test requires email/SMS token interception")
        self.log(Severity.INFO,
                "Manual verification: Request reset token -> Consume token -> Attempt reuse of same token")
    
    def test_mfa_bypass_resistance(self):
        """Test Multi-Factor Authentication (MFA) step bypass resistance"""
        print("\n[TEST] MFA Bypass Resistance")
        
        mfa_protected_paths = [
            "/api/v1/admin/settings",
            "/api/v1/roles/permissions"
        ]
        
        if not self.sessions['admin'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No admin session configured")
            return
        
        self.log(Severity.INFO,
                "MFA bypass test requires active MFA configuration on target user account")
        self.log(Severity.INFO,
                "Manual verification: Authenticate primary factor -> Bypass OTP step -> Access protected resources")
