"""
Module 3: Multi-Tenancy & Data Isolation
Tests tenant isolation, data scoping, and cross-tenant access prevention
"""

from sentinel.base_test import BaseSecurityTest, Severity


class MultiTenancyTests(BaseSecurityTest):
    """Multi-Tenancy & Data Isolation Tests"""
    
    def run_tests(self):
        """Run all multi-tenancy security tests"""
        print("\n" + "="*60)
        print("MODULE 3: MULTI-TENANCY & DATA ISOLATION")
        print("="*60)
        
        self.test_tenant_id_tampering()
        self.test_foreign_key_scoping()
        self.test_global_resources_isolation()
        self.test_search_cross_tenant_leakage()
        self.test_analytics_cross_tenant_leakage()
        self.test_centralized_resources()
    
    def test_tenant_id_tampering(self):
        """Test tenant ID tampering in requests"""
        print("\n[TEST] Tenant ID Tampering")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        # Try to create/update resource with different tenant_id
        tampered_payloads = [
            {"name": "Test", "agency_id": 999},
            {"name": "Test", "tenant_id": "different-tenant"},
            {"name": "Test", "organization_id": 999}
        ]
        
        for payload in tampered_payloads:
            r = self.request(self.sessions['agency_a'], "POST",
                           "/api/v1/enquiries",
                           json=payload)
            
            if r and r.status_code == 200:
                response_data = r.json()
                # Check if the tampered tenant_id was accepted
                if any(response_data.get(key) == payload.get(key) 
                      for key in ['agency_id', 'tenant_id', 'organization_id']):
                    self.log(Severity.CRITICAL,
                            "Tenant ID tampering successful",
                            {"payload": payload})
                else:
                    self.log(Severity.PASSED,
                            "Tenant ID properly overridden by server")
            elif r and r.status_code in (403, 422):
                self.log(Severity.PASSED, "Tenant ID tampering rejected")
    
    def test_foreign_key_scoping(self):
        """Test foreign key scoping enforcement"""
        print("\n[TEST] Foreign Key Scoping Enforcement")
        
        # Test if you can assign resources from other tenants
        # e.g., assign a student from Agency A to a program from Agency B
        
        self.log(Severity.INFO,
                "Foreign key scoping test requires cross-tenant resource IDs")
        self.log(Severity.INFO,
                "Manual verification: Get resource ID from Agency A → Try assigning to Agency B resource")
    
    def test_global_resources_isolation(self):
        """Test global resources (Universities, Programs) isolation"""
        print("\n[TEST] Global Resources Isolation")
        
        # Test centralized resources that should be read-only or properly scoped
        global_endpoints = [
            "/api/v1/universities",
            "/api/v1/programs",
            "/api/v1/courses"
        ]
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        for endpoint in global_endpoints:
            # Test read access
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            if r and r.status_code == 200:
                self.log(Severity.PASSED, f"Read access to global resource: {endpoint}")
            
            # Test write access (should be restricted)
            r = self.request(self.sessions['agency_a'], "POST",
                           endpoint,
                           json={"name": "Tampered University"})
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"Agency can create global resource: {endpoint}",
                        {"endpoint": endpoint})
            elif r and r.status_code in (403, 405):
                self.log(Severity.PASSED,
                        f"Global resource creation properly restricted: {endpoint}")
    
    def test_search_cross_tenant_leakage(self):
        """Test search endpoints for cross-tenant data leakage"""
        print("\n[TEST] Search Cross-Tenant Leakage")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        search_endpoints = [
            "/api/v1/search?q=test",
            "/api/v1/students/search?query=test",
            "/api/v1/enquiries/search?query=test",
            "/api/v1/users/search?query=test"
        ]
        
        for endpoint in search_endpoints:
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if r and r.status_code == 200:
                data = r.json()
                results = data.get('data', []) or data.get('results', [])
                
                # Check if results contain tenant identifiers
                # This is a heuristic check - adjust based on your data structure
                if results:
                    self.log(Severity.INFO,
                            f"Search returned {len(results)} results from {endpoint}")
                    # In a real test, you'd verify these all belong to the same tenant
                    self.log(Severity.INFO,
                            "Manual verification required: Ensure all results belong to current tenant")
    
    def test_analytics_cross_tenant_leakage(self):
        """Test analytics/reports for cross-tenant data leakage"""
        print("\n[TEST] Analytics Cross-Tenant Leakage")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        analytics_endpoints = [
            "/api/v1/analytics/dashboard",
            "/api/v1/reports/summary",
            "/api/v1/statistics/overview"
        ]
        
        for endpoint in analytics_endpoints:
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if r and r.status_code == 200:
                data = r.json()
                self.log(Severity.INFO,
                        f"Analytics endpoint accessible: {endpoint}")
                self.log(Severity.INFO,
                        "Manual verification: Ensure aggregates don't include other tenants' data")
    
    def test_centralized_resources(self):
        """Test centralized resources (Documents, Reports) isolation"""
        print("\n[TEST] Centralized Resources Isolation")
        
        # Test high-risk shared surfaces
        centralized_endpoints = [
            "/api/v1/documents",
            "/api/v1/reports",
            "/api/v1/templates"
        ]
        
        if not all([
            self.sessions['agency_a'].cookies.get('laravel_session'),
            self.sessions['agency_b'].cookies.get('laravel_session')
        ]):
            self.log(Severity.INFO, "Skipping: Requires agency_a and agency_b sessions")
            return
        
        for endpoint in centralized_endpoints:
            # Get Agency A's resources
            r_a = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if not r_a or r_a.status_code != 200:
                continue
            
            data_a = r_a.json()
            resources_a = data_a.get('data', [])
            
            if not resources_a:
                continue
            
            # Get first resource ID from Agency A
            resource_id = resources_a[0].get('id') or resources_a[0].get('uuid')
            
            if not resource_id:
                continue
            
            # Try to access Agency A's resource from Agency B
            r_b = self.request(self.sessions['agency_b'], "GET",
                             f"{endpoint}/{resource_id}")
            
            if r_b and r_b.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Cross-tenant access: Agency B accessed Agency A's resource",
                        {"endpoint": endpoint, "resource_id": resource_id})
            elif r_b and r_b.status_code in (403, 404):
                self.log(Severity.PASSED,
                        f"Cross-tenant access properly blocked: {endpoint}")
