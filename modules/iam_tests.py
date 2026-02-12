"""
Module 1: Identity, Authentication & Session Security (IAM)
Tests authentication mechanisms, session management, and identity controls
"""

from pentest.base_test import BaseSecurityTest, Severity
import time
import uuid


class IAMSecurityTests(BaseSecurityTest):
    """Identity, Authentication & Session Security Tests"""
    
    def run_tests(self):
        """Run all IAM security tests"""
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
        """Test that protected routes require authentication"""
        print("\n[TEST] Public vs Protected Access")
        
        protected_paths = [
            "/dashboard",
            "/users/users",
            "/api/v1/topbar/notifications/recent",
            "/users/roles/permissions",
            "/portal/profile",
            "/api/v1/admissions",
            "/api/v1/enquiries",
            "/api/v1/students"
        ]
        
        session = self.sessions['unauthenticated']
        
        for path in protected_paths:
            r = self.request(session, "GET", path, allow_redirects=False)
            
            if not r:
                continue
                
            if r.status_code == 200:
                self.log(Severity.CRITICAL, 
                        f"Public access to protected endpoint: {path}",
                        {"status_code": r.status_code, "path": path})
            elif r.status_code in (301, 302):
                location = r.headers.get("Location", "")
                if "login" in location.lower():
                    self.log(Severity.PASSED, f"Properly redirected to login: {path}")
                else:
                    self.log(Severity.MEDIUM,
                            f"Redirect but not to login: {path}",
                            {"location": location})
            elif r.status_code == 401:
                self.log(Severity.PASSED, f"Unauthorized (401) as expected: {path}")
            elif r.status_code == 403:
                self.log(Severity.PASSED, f"Forbidden (403) as expected: {path}")
            else:
                self.log(Severity.LOW,
                        f"Unexpected status for protected path: {path}",
                        {"status_code": r.status_code})
    
    def test_session_persistence(self):
        """Test session persistence and timeout"""
        print("\n[TEST] Session Persistence")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test that valid session works
        r = self.request(self.sessions['user_a'], "GET", "/dashboard")
        
        if r and r.status_code == 200:
            self.log(Severity.PASSED, "Valid session accepted")
        else:
            self.log(Severity.HIGH, 
                    "Valid session rejected",
                    {"status_code": r.status_code if r else "None"})
    
    def test_csrf_protection(self):
        """Test CSRF protection on state-changing operations"""
        print("\n[TEST] CSRF Protection")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Try POST without CSRF token
        session = self.sessions['user_a']
        original_tokens = self.csrf_tokens.copy()
        self.csrf_tokens.clear()  # Temporarily remove CSRF tokens
        
        r = session.post(
            f"{self.base_url}/api/v1/test-endpoint",
            headers={'Accept': 'application/json'},
            json={"test": "data"}
        )
        
        self.csrf_tokens = original_tokens  # Restore tokens
        
        if r and r.status_code in (419, 403):
            self.log(Severity.PASSED, "CSRF protection active (419/403 without token)")
        elif r and r.status_code == 404:
            self.log(Severity.INFO, "Test endpoint not found (expected)")
        else:
            self.log(Severity.MEDIUM,
                    "CSRF protection unclear",
                    {"status_code": r.status_code if r else "None"})
    
    def test_token_invalidation_after_logout(self):
        """Test that tokens are invalidated after logout"""
        print("\n[TEST] Token Invalidation After Logout")
        
        # This test requires a dedicated test session
        # In production, you'd create a fresh login, capture token, logout, retry
        self.log(Severity.INFO, 
                "Token invalidation test requires dedicated test account")
        self.log(Severity.INFO, 
                "Manual verification: Login → Capture session → Logout → Retry with old session")
    
    def test_concurrent_session_limits(self):
        """Test concurrent session limits"""
        print("\n[TEST] Concurrent Session Limits")
        
        # Test if same user can have multiple active sessions
        # This requires multiple valid sessions for the same user
        self.log(Severity.INFO,
                "Concurrent session test requires multiple sessions for same user")
        self.log(Severity.INFO,
                "Manual verification: Login from 2+ devices → Check if both remain active")
    
    def test_session_fixation(self):
        """Test resistance to session fixation attacks"""
        print("\n[TEST] Session Fixation Resistance")
        
        # Session fixation: attacker sets victim's session ID before login
        # After login, session ID should regenerate
        
        session = self.sessions['unauthenticated']
        
        # Set a known session ID
        fixed_session_id = str(uuid.uuid4())
        session.cookies.set('laravel_session', fixed_session_id)
        
        # Attempt login (this would require valid credentials)
        # In a real test, you'd login and check if session ID changed
        
        self.log(Severity.INFO,
                "Session fixation test requires login flow")
        self.log(Severity.INFO,
                "Manual verification: Set session cookie → Login → Verify session ID changed")
    
    def test_device_ip_change_behavior(self):
        """Test behavior when device/IP changes mid-session"""
        print("\n[TEST] Device/IP Change Behavior")
        
        # This test requires proxy/VPN to change IP
        self.log(Severity.INFO,
                "Device/IP change test requires network manipulation")
        self.log(Severity.INFO,
                "Manual verification: Login → Change IP/User-Agent → Verify session handling")
    
    def test_password_reset_token_reuse(self):
        """Test that password reset tokens cannot be reused"""
        print("\n[TEST] Password Reset Token Reuse")
        
        # Test password reset flow
        # 1. Request reset
        # 2. Use token
        # 3. Try to reuse same token
        
        self.log(Severity.INFO,
                "Password reset token test requires email integration")
        self.log(Severity.INFO,
                "Manual verification: Reset password → Capture token → Use once → Retry same token")
    
    def test_mfa_bypass_resistance(self):
        """Test MFA bypass resistance (if MFA is enabled)"""
        print("\n[TEST] MFA Bypass Resistance")
        
        # Check if MFA can be bypassed
        # - Direct access to post-MFA endpoints
        # - Session manipulation
        # - API endpoint bypass
        
        mfa_protected_paths = [
            "/api/v1/admin/settings",
            "/users/roles/permissions"
        ]
        
        if not self.sessions['admin'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No admin session configured")
            return
        
        # This assumes MFA is enabled for admin
        # In reality, you'd need to check MFA status first
        
        self.log(Severity.INFO,
                "MFA bypass test requires MFA-enabled account")
        self.log(Severity.INFO,
                "Manual verification: Enable MFA → Login (stop before MFA) → Try accessing protected resources")
