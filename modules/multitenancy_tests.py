"""
Module 3: Multi-Tenancy & Data Isolation
Tests tenant isolation, data scoping, and cross-tenant access prevention
"""

from sentinel.base_test import BaseSecurityTest, Severity


class MultiTenancyTests(BaseSecurityTest):
    """
    Multi-Tenancy & Data Isolation Security Test Suite
    
    Evaluates multi-tenant SaaS architectures for data isolation boundaries, 
    tenant identifier tampering, foreign key scoping, and cross-tenant data leakage.
    """
    
    def run_tests(self):
        """Orchestrate and execute all multi-tenancy security tests"""
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
        """
        Test Tenant ID Tampering in API Payloads
        
        Attack Vector:
        Attempting to override or assign client-supplied tenant identifiers 
        (e.g., tenant_id, agency_id, organization_id) during resource creation or modification.
        
        Expected Result:
        The server MUST ignore client-supplied tenant IDs and enforce tenancy from session context, 
        or reject tampered payloads with 422/403.
        """
        print("\n[TEST] Tenant ID Parameter Tampering")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a (Tenant A) session configured")
            return
        
        # Generic multi-tenant payload tampering tests
        tampered_payloads = [
            {"name": "Tampered Resource", "agency_id": 999},
            {"name": "Tampered Resource", "tenant_id": "different-tenant-uuid"},
            {"name": "Tampered Resource", "organization_id": 999}
        ]
        
        for payload in tampered_payloads:
            r = self.request(self.sessions['agency_a'], "POST",
                           "/api/v1/records",
                           json=payload)
            
            if r and r.status_code == 200:
                response_data = r.json()
                # Check if the tampered tenant_id was accepted by the server
                if any(response_data.get(key) == payload.get(key) 
                      for key in ['agency_id', 'tenant_id', 'organization_id']):
                    self.log(Severity.CRITICAL,
                            "Tenant ID tampering vulnerability: Server accepted foreign tenant ID",
                            {"payload": payload})
                else:
                    self.log(Severity.PASSED,
                            "Tenant ID properly overridden by server session context")
            elif r and r.status_code in (403, 422, 400):
                self.log(Severity.PASSED, "Tenant ID tampering properly rejected by server")
            elif r and r.status_code == 404:
                self.log(Severity.INFO, "Test resource creation endpoint not found (expected)")
    
    def test_foreign_key_scoping(self):
        """
        Test Foreign Key Scoping Enforcement (Cross-Tenant Relational Assignment)
        
        Attack Vector:
        Assigning a relational record belonging to Tenant B (e.g. user_id, department_id, item_id) 
        to a new or existing resource created by Tenant A.
        """
        print("\n[TEST] Foreign Key Scoping Enforcement")
        self.log(Severity.INFO,
                "Foreign key scoping test requires pre-existing cross-tenant resource IDs")
        self.log(Severity.INFO,
                "Manual verification: Fetch resource ID from Tenant A -> Attempt linking it to a Tenant B parent resource")
    
    def test_global_resources_isolation(self):
        """
        Test Global Shared Resources vs Tenant-Scoped Resources
        
        Verifies that global system resources (e.g. system categories, global lookup tables) 
        are read-only for tenant accounts and cannot be tampered with via HTTP POST/PUT/DELETE.
        """
        print("\n[TEST] Global Shared Resources Access & Isolation")
        
        # Generic enterprise shared global endpoints
        global_endpoints = [
            "/api/v1/system/categories",
            "/api/v1/system/countries",
            "/api/v1/system/templates"
        ]
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        for endpoint in global_endpoints:
            # Test read access (Allowed)
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            if r and r.status_code == 200:
                self.log(Severity.PASSED, f"Read access verified for global resource: {endpoint}")
            
            # Test write access (Must be Restricted)
            r = self.request(self.sessions['agency_a'], "POST",
                           endpoint,
                           json={"name": "Tampered Global Resource"})
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"Tenant account can alter shared global resource: {endpoint}",
                        {"endpoint": endpoint})
            elif r and r.status_code in (403, 405, 401):
                self.log(Severity.PASSED,
                        f"Global resource modification properly restricted: {endpoint}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO, f"Global resource endpoint not found (expected): {endpoint}")

    def test_search_cross_tenant_leakage(self):
        """
        Test Global Search & Index Queries for Cross-Tenant Data Leaks
        
        Verifies that search indexes filter query results strictly by active tenant context.
        """
        print("\n[TEST] Search Query Cross-Tenant Data Isolation")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        generic_search_endpoints = [
            "/api/v1/search?query=test",
            "/api/v1/users/search?query=test",
            "/api/v1/records/search?query=test"
        ]
        
        for endpoint in generic_search_endpoints:
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if r and r.status_code == 200:
                data = r.json()
                results = data.get('data', []) or data.get('results', [])
                
                if results:
                    self.log(Severity.INFO,
                            f"Search endpoint returned {len(results)} records: {endpoint}")
                    self.log(Severity.INFO,
                            "Manual verification required: Ensure all search results match active tenant ID")
            elif r and r.status_code == 404:
                self.log(Severity.INFO, f"Search endpoint not found (expected): {endpoint}")

    def test_analytics_cross_tenant_leakage(self):
        """
        Test Analytics & Reporting Aggregations for Cross-Tenant Data Leaks
        
        Verifies that reporting metrics and dashboard counts do not include foreign tenant data.
        """
        print("\n[TEST] Analytics & Report Metrics Tenant Isolation")
        
        if not self.sessions['agency_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No agency_a session configured")
            return
        
        analytics_endpoints = [
            "/api/v1/analytics/dashboard",
            "/api/v1/reports/summary",
            "/api/v1/metrics/overview"
        ]
        
        for endpoint in analytics_endpoints:
            r = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if r and r.status_code == 200:
                self.log(Severity.INFO, f"Analytics endpoint accessible: {endpoint}")
                self.log(Severity.INFO, "Manual verification: Ensure aggregate figures exclude external tenants")
            elif r and r.status_code == 404:
                self.log(Severity.INFO, f"Analytics endpoint not found (expected): {endpoint}")

    def test_centralized_resources(self):
        """
        Test Cross-Tenant Isolation on Centralized Resource Endpoints (Documents, Invoices)
        
        Verifies that Tenant B cannot access specific resource IDs created by Tenant A.
        """
        print("\n[TEST] Centralized Resource Access Isolation (Tenant A vs Tenant B)")
        
        centralized_endpoints = [
            "/api/v1/documents",
            "/api/v1/reports",
            "/api/v1/invoices"
        ]
        
        if not all([
            self.sessions['agency_a'].cookies.get('laravel_session'),
            self.sessions['agency_b'].cookies.get('laravel_session')
        ]):
            self.log(Severity.INFO, "Skipping: Requires both agency_a (Tenant A) and agency_b (Tenant B) sessions")
            return
        
        for endpoint in centralized_endpoints:
            # Query Tenant A resources
            r_a = self.request(self.sessions['agency_a'], "GET", endpoint)
            
            if not r_a or r_a.status_code != 200:
                continue
            
            data_a = r_a.json()
            resources_a = data_a.get('data', [])
            
            if not resources_a:
                continue
            
            # Extract first resource ID from Tenant A
            resource_id = resources_a[0].get('id') or resources_a[0].get('uuid')
            
            if not resource_id:
                continue
            
            # Attempt to access Tenant A's resource using Tenant B's session
            r_b = self.request(self.sessions['agency_b'], "GET",
                             f"{endpoint}/{resource_id}")
            
            if r_b and r_b.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Cross-tenant access violation: Tenant B accessed Tenant A's resource",
                        {"endpoint": endpoint, "resource_id": resource_id})
            elif r_b and r_b.status_code in (403, 404):
                self.log(Severity.PASSED,
                        f"Cross-tenant access properly blocked: {endpoint}")
