"""
Module 12: Human-Driven & Process Attacks
Tests for human errors and process vulnerabilities
"""

from sentinel.base_test import BaseSecurityTest, Severity


class HumanProcessTests(BaseSecurityTest):
    """Human-Driven & Process Attack Tests"""
    
    def run_tests(self):
        """Run all human/process tests"""
        print("\n" + "="*60)
        print("MODULE 12: HUMAN-DRIVEN & PROCESS ATTACKS")
        print("="*60)
        
        self.test_default_credentials()
        self.test_over_permissioned_roles()
    
    def test_default_credentials(self):
        """Test for default credentials"""
        print("\n[TEST] Default Credentials")
        
        default_creds = [
            {"email": "admin@admin.com", "password": "admin"},
            {"email": "admin@example.com", "password": "password"},
            {"email": "test@test.com", "password": "test123"}
        ]
        
        for creds in default_creds:
            r = self.request(self.sessions['unauthenticated'], "POST",
                           "/portal/auth/login",
                           json=creds)
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Default credentials work: {creds['email']}")
            else:
                self.log(Severity.PASSED,
                        f"Default credentials rejected: {creds['email']}")
    
    def test_over_permissioned_roles(self):
        """Test for over-permissioned roles"""
        print("\n[TEST] Over-permissioned Roles")
        
        self.log(Severity.INFO,
                "Over-permissioned roles test requires RBAC analysis")
        self.log(Severity.INFO,
                "Manual verification: Review role permissions for principle of least privilege")
