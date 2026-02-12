"""
Module 2: Authorization & RBAC Integrity
Tests role-based access control, permission enforcement, and authorization logic
"""

from sentinel.base_test import BaseSecurityTest, Severity
import uuid


class RBACSecurityTests(BaseSecurityTest):
    """Authorization & RBAC Integrity Tests"""
    
    def run_tests(self):
        """Run all RBAC security tests"""
        print("\n" + "="*60)
        print("MODULE 2: AUTHORIZATION & RBAC INTEGRITY")
        print("="*60)
        
        self.test_vertical_privilege_escalation()
        self.test_horizontal_access_control()
        self.test_bulk_permission_abuse()
        self.test_cross_tenant_access()
        self.test_permission_shadowing()
        self.test_permission_removal_reflection()
        self.test_api_vs_ui_permission_mismatch()
    
    def test_vertical_privilege_escalation(self):
        """Test User → Admin privilege escalation"""
        print("\n[TEST] Vertical Privilege Escalation (User → Admin)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        admin_only_paths = [
            "/users/users/create",
            "/users/roles/create",
            "/api/v1/admin/settings",
            "/api/v1/system/config",
            "/users/roles/permissions"
        ]
        
        for path in admin_only_paths:
            r = self.request(self.sessions['user_a'], "GET", path, allow_redirects=False)
            
            if not r:
                continue
            
            if r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"User accessed admin-only endpoint: {path}",
                        {"status_code": r.status_code})
            elif r.status_code == 403:
                self.log(Severity.PASSED, f"Admin endpoint properly protected: {path}")
            elif r.status_code in (301, 302, 401):
                self.log(Severity.PASSED, f"Admin endpoint redirected/unauthorized: {path}")
            else:
                self.log(Severity.LOW,
                        f"Unexpected response for admin endpoint: {path}",
                        {"status_code": r.status_code})
    
    def test_horizontal_access_control(self):
        """Test same-role cross-user access (User A → User B)"""
        print("\n[TEST] Horizontal Access Control (User A → User B)")
        
        if not all([
            self.sessions['user_a'].cookies.get('laravel_session'),
            self.sessions['user_b'].cookies.get('laravel_session')
        ]):
            self.log(Severity.INFO, "Skipping: Requires both user_a and user_b sessions")
            return
        
        # Get User A's own data
        r_a = self.request(self.sessions['user_a'], "GET", "/api/v1/users/me")
        if not r_a or r_a.status_code != 200:
            self.log(Severity.INFO, "Could not fetch User A data")
            return
        
        user_a_data = r_a.json()
        user_a_uuid = user_a_data.get('uuid') or user_a_data.get('id')
        
        # Get User B's own data
        r_b = self.request(self.sessions['user_b'], "GET", "/api/v1/users/me")
        if not r_b or r_b.status_code != 200:
            self.log(Severity.INFO, "Could not fetch User B data")
            return
        
        user_b_data = r_b.json()
        user_b_uuid = user_b_data.get('uuid') or user_b_data.get('id')
        
        if not user_b_uuid:
            self.log(Severity.INFO, "Could not extract User B UUID")
            return
        
        # Try User A accessing User B's profile
        r = self.request(self.sessions['user_a'], "GET", f"/api/v1/users/{user_b_uuid}")
        
        if r and r.status_code == 200:
            self.log(Severity.CRITICAL,
                    "Horizontal access violation: User A accessed User B's profile",
                    {"user_a": user_a_uuid, "user_b": user_b_uuid})
        elif r and r.status_code == 403:
            self.log(Severity.PASSED, "Horizontal access properly blocked")
        else:
            self.log(Severity.MEDIUM,
                    "Horizontal access test inconclusive",
                    {"status_code": r.status_code if r else "None"})
        
        # Try User A updating User B's data
        r = self.request(self.sessions['user_a'], "PATCH", 
                        f"/api/v1/users/{user_b_uuid}",
                        json={"name": "Hacked"})
        
        if r and r.status_code == 200:
            self.log(Severity.CRITICAL,
                    "Horizontal access violation: User A modified User B's data",
                    {"user_a": user_a_uuid, "user_b": user_b_uuid})
        elif r and r.status_code in (403, 404):
            self.log(Severity.PASSED, "Horizontal modification properly blocked")
    
    def test_bulk_permission_abuse(self):
        """Test bulk permission update abuse"""
        print("\n[TEST] Bulk Permission Update Abuse")
        
        if not self.sessions['admin'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No admin session configured")
            return
        
        # Test with admin (should work)
        payload = {
            "role_id": 1,
            "permissions": [{"permission_id": 1, "action": "assign"}]
        }
        
        r = self.request(self.sessions['admin'], "POST",
                        "/users/roles/bulk-update-permissions",
                        json=payload, allow_redirects=False)
        
        if r and r.status_code == 200:
            self.log(Severity.PASSED, "Admin can perform bulk permission updates")
        elif r and r.status_code == 404:
            self.log(Severity.INFO, "Bulk permission endpoint not found")
        
        # Test with regular user (should fail)
        if self.sessions['user_a'].cookies.get('laravel_session'):
            r = self.request(self.sessions['user_a'], "POST",
                            "/users/roles/bulk-update-permissions",
                            json=payload, allow_redirects=False)
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        "Regular user can perform bulk permission updates")
            elif r and r.status_code in (403, 401):
                self.log(Severity.PASSED, "Bulk permission update properly restricted")
    
    def test_cross_tenant_access(self):
        """Test cross-tenant/cross-agency access"""
        print("\n[TEST] Cross-Tenant/Cross-Agency Access")
        
        if not all([
            self.sessions['agency_a'].cookies.get('laravel_session'),
            self.sessions['agency_b'].cookies.get('laravel_session')
        ]):
            self.log(Severity.INFO, "Skipping: Requires agency_a and agency_b sessions")
            return
        
        # This test requires knowing resource IDs from each agency
        # In practice, you'd query Agency A's resources, then try to access from Agency B
        
        self.log(Severity.INFO,
                "Cross-tenant test requires agency-specific resource IDs")
        self.log(Severity.INFO,
                "Manual verification: Create resource in Agency A → Try accessing from Agency B")
    
    def test_permission_shadowing(self):
        """Test permission shadowing (conflicting permissions)"""
        print("\n[TEST] Permission Shadowing")
        
        # Permission shadowing: when a user has conflicting permissions
        # e.g., role grants "view_users" but direct permission denies it
        
        self.log(Severity.INFO,
                "Permission shadowing test requires complex permission setup")
        self.log(Severity.INFO,
                "Manual verification: Grant role permission → Deny direct permission → Test access")
    
    def test_permission_removal_reflection(self):
        """Test that permission removal is reflected in active sessions"""
        print("\n[TEST] Permission Removal Reflection")
        
        # Test if removing a permission immediately affects active sessions
        # or if sessions cache permissions
        
        self.log(Severity.INFO,
                "Permission removal test requires admin access to modify permissions")
        self.log(Severity.INFO,
                "Manual verification: Active session → Remove permission → Retry action without re-login")
    
    def test_api_vs_ui_permission_mismatch(self):
        """Test for API vs UI permission mismatches"""
        print("\n[TEST] API vs UI Permission Mismatch")
        
        # Sometimes UI hides actions but API still allows them
        # Test common CRUD operations via API that might be hidden in UI
        
        test_endpoints = [
            {"method": "POST", "path": "/api/v1/users", "action": "create_user"},
            {"method": "DELETE", "path": "/api/v1/users/test-uuid", "action": "delete_user"},
            {"method": "PATCH", "path": "/api/v1/roles/1", "action": "modify_role"}
        ]
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        for endpoint in test_endpoints:
            r = self.request(self.sessions['user_a'], 
                           endpoint['method'],
                           endpoint['path'],
                           json={"test": "data"})
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"User can {endpoint['action']} via API (check if UI allows this)",
                        {"endpoint": endpoint['path']})
            elif r and r.status_code in (403, 401):
                self.log(Severity.PASSED,
                        f"API properly blocks {endpoint['action']}")
