"""
Module 6: API Security (OWASP API Top 10)
Tests API-specific vulnerabilities and attack vectors
"""

from sentinel.base_test import BaseSecurityTest, Severity
import time


class APISecurityTests(BaseSecurityTest):
    """API Security Tests (OWASP API Top 10)"""
    
    def run_tests(self):
        """Run all API security tests"""
        print("\n" + "="*60)
        print("MODULE 6: API SECURITY (OWASP API TOP 10)")
        print("="*60)
        
        self.test_over_fetching()
        self.test_mass_enumeration()
        self.test_filter_injection()
        self.test_verb_confusion()
        self.test_batch_endpoint_abuse()
        self.test_pagination_abuse()
    
    def test_over_fetching(self):
        """Test over-fetching sensitive fields"""
        print("\n[TEST] Over-fetching Sensitive Fields")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if API returns sensitive fields
        sensitive_include_params = [
            "?include=password",
            "?include=roles,permissions,password_hash",
            "?include=*",
            "?fields=*",
            "?with=roles.permissions.users"
        ]
        
        for param in sensitive_include_params:
            r = self.request(self.sessions['user_a'], "GET",
                           f"/api/v1/users/me{param}")
            
            if r and r.status_code == 200:
                data = r.json()
                # Check for sensitive fields
                sensitive_fields = ['password', 'password_hash', 'remember_token', 'api_token']
                found_sensitive = [field for field in sensitive_fields if field in str(data)]
                
                if found_sensitive:
                    self.log(Severity.HIGH,
                            f"Over-fetching: Sensitive fields exposed via {param}",
                            {"fields": found_sensitive})
                else:
                    self.log(Severity.PASSED,
                            f"No sensitive fields in response for {param}")
    
    def test_mass_enumeration(self):
        """Test mass enumeration via pagination"""
        print("\n[TEST] Mass Enumeration")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if we can enumerate all users/resources
        r = self.request(self.sessions['user_a'], "GET",
                       "/api/v1/users?per_page=1000000")
        
        if r and r.status_code == 200:
            data = r.json()
            count = len(data.get('data', []))
            
            if count > 100:
                self.log(Severity.MEDIUM,
                        f"Mass enumeration possible: Retrieved {count} users",
                        {"count": count})
            else:
                self.log(Severity.PASSED,
                        f"Pagination limit enforced (max {count} results)")
        
        # Test sequential ID enumeration
        for user_id in range(1, 11):
            r = self.request(self.sessions['user_a'], "GET",
                           f"/api/v1/users/{user_id}")
            
            if r and r.status_code == 200:
                if user_id == 1:
                    self.log(Severity.LOW,
                            "Sequential ID enumeration possible",
                            {"note": "Consider using UUIDs instead of sequential IDs"})
                    break
    
    def test_filter_injection(self):
        """Test filter injection attacks"""
        print("\n[TEST] Filter Injection")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        injection_payloads = [
            "?filter[role_id]=1 OR 1=1",
            "?filter[created_at]=>2020-01-01",
            "?filter[id][in][]=1&filter[id][in][]=2&filter[id][in][]=3",
            "?sort=-id&filter[deleted_at][null]=false"  # Try to access soft-deleted records
        ]
        
        for payload in injection_payloads:
            r = self.request(self.sessions['user_a'], "GET",
                           f"/api/v1/users{payload}")
            
            if r and r.status_code == 200:
                data = r.json()
                self.log(Severity.INFO,
                        f"Filter accepted: {payload}",
                        {"result_count": len(data.get('data', []))})
    
    def test_verb_confusion(self):
        """Test HTTP verb confusion (POST vs PUT)"""
        print("\n[TEST] HTTP Verb Confusion")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if different verbs bypass authorization
        test_resource = "/api/v1/users/test-uuid"
        payload = {"name": "Modified"}
        
        verbs = ["PUT", "PATCH", "POST"]
        
        for verb in verbs:
            r = self.request(self.sessions['user_a'], verb,
                           test_resource, json=payload)
            
            if r and r.status_code == 200:
                self.log(Severity.INFO,
                        f"Verb {verb} accepted for resource update")
    
    def test_batch_endpoint_abuse(self):
        """Test batch endpoint abuse"""
        print("\n[TEST] Batch Endpoint Abuse")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if batch endpoints can be abused
        batch_payload = {
            "operations": [{"id": i, "action": "delete"} for i in range(1, 1001)]
        }
        
        r = self.request(self.sessions['user_a'], "POST",
                       "/api/v1/batch",
                       json=batch_payload)
        
        if r and r.status_code == 200:
            self.log(Severity.MEDIUM,
                    "Batch endpoint accepted 1000 operations (check for limits)")
        elif r and r.status_code == 422:
            self.log(Severity.PASSED,
                    "Batch endpoint has operation limits")
    
    def test_pagination_abuse(self):
        """Test pagination abuse"""
        print("\n[TEST] Pagination Abuse")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test excessive pagination limits
        r = self.request(self.sessions['user_a'], "GET",
                       "/api/v1/users?per_page=999999")
        
        if r and r.status_code == 200:
            data = r.json()
            count = len(data.get('data', []))
            
            if count > 100:
                self.log(Severity.MEDIUM,
                        f"Pagination limit too high: {count} records returned")
            else:
                self.log(Severity.PASSED,
                        f"Pagination properly limited to {count} records")
