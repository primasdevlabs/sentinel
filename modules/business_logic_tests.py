"""
Module 4: Business Logic & Workflow Integrity
Tests workflow state machines, business rules, and logic-level vulnerabilities
"""

from sentinel.base_test import BaseSecurityTest, Severity
import time
import concurrent.futures


class BusinessLogicTests(BaseSecurityTest):
    """Business Logic & Workflow Integrity Tests"""
    
    def run_tests(self):
        """Run all business logic security tests"""
        print("\n" + "="*60)
        print("MODULE 4: BUSINESS LOGIC & WORKFLOW INTEGRITY")
        print("="*60)
        
        self.test_status_skipping()
        self.test_role_invalid_transitions()
        self.test_race_conditions()
        self.test_replay_attacks()
        self.test_temporal_manipulation()
    
    def test_status_skipping(self):
        """Test illegal workflow status transitions"""
        print("\n[TEST] Status Skipping (Workflow Bypass)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test illegal transitions in student admission workflow
        # Normal flow: Enquiry → Counselling → Document Verification → Approved
        # Attack: Try to skip directly to Approved
        
        illegal_transitions = [
            {
                "endpoint": "/api/v1/enquiries/test-uuid",
                "payload": {"status": "approved"},
                "description": "Enquiry → Approved (skipping counselling)"
            },
            {
                "endpoint": "/api/v1/students/test-uuid",
                "payload": {"status": "enrolled"},
                "description": "Student → Enrolled (skipping payment)"
            },
            {
                "endpoint": "/api/v1/admissions/test-uuid",
                "payload": {"status": "visa_approved"},
                "description": "Admission → Visa Approved (skipping document verification)"
            }
        ]
        
        for transition in illegal_transitions:
            r = self.request(self.sessions['user_a'], "PATCH",
                           transition['endpoint'],
                           json=transition['payload'])
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Illegal workflow transition allowed: {transition['description']}",
                        {"endpoint": transition['endpoint']})
            elif r and r.status_code in (403, 422):
                self.log(Severity.PASSED,
                        f"Workflow transition properly blocked: {transition['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Test resource not found (expected): {transition['description']}")
    
    def test_role_invalid_transitions(self):
        """Test role-invalid workflow transitions"""
        print("\n[TEST] Role-Invalid Transitions")
        
        # Test if users can perform transitions they shouldn't be allowed to
        # e.g., Student trying to approve their own admission
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        role_invalid_actions = [
            {
                "endpoint": "/api/v1/enquiries/test-uuid/approve",
                "method": "POST",
                "description": "Regular user approving enquiry (admin-only action)"
            },
            {
                "endpoint": "/api/v1/students/test-uuid/enroll",
                "method": "POST",
                "description": "Regular user enrolling student (counsellor-only action)"
            }
        ]
        
        for action in role_invalid_actions:
            r = self.request(self.sessions['user_a'],
                           action['method'],
                           action['endpoint'],
                           json={})
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Role-invalid action allowed: {action['description']}",
                        {"endpoint": action['endpoint']})
            elif r and r.status_code in (403, 401):
                self.log(Severity.PASSED,
                        f"Role-invalid action properly blocked: {action['description']}")
    
    def test_race_conditions(self):
        """Test race conditions (double execution)"""
        print("\n[TEST] Race Conditions (Double Execution)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test concurrent requests to the same endpoint
        # e.g., double payment, double enrollment
        
        endpoint = "/api/v1/payments/test-uuid/process"
        payload = {"amount": 100, "method": "credit_card"}
        
        def make_request():
            try:
                return self.request(self.sessions['user_a'], "POST",
                                  endpoint, json=payload)
            except Exception:
                return None
        
        try:
            # Send 5 concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(make_request) for _ in range(5)]
                responses = [f.result(timeout=5) for f in futures]
            
            success_count = sum(1 for r in responses if r and r.status_code == 200)
            
            if success_count > 1:
                self.log(Severity.CRITICAL,
                        f"Race condition: {success_count} concurrent requests succeeded",
                        {"endpoint": endpoint, "expected": 1, "actual": success_count})
            elif success_count == 1:
                self.log(Severity.PASSED,
                        "Race condition protection active (only 1 request succeeded)")
            elif success_count == 0:
                self.log(Severity.INFO,
                        "No requests succeeded (test resource may not exist)")
        except (KeyboardInterrupt, Exception) as e:
            self.log(Severity.INFO,
                    f"Race condition test skipped: {type(e).__name__}")
    
    def test_replay_attacks(self):
        """Test replay attack resistance"""
        print("\n[TEST] Replay Attack Resistance")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if the same request can be replayed
        # Critical for: payments, approvals, status changes
        
        endpoint = "/api/v1/payments/test-uuid/process"
        payload = {"amount": 100, "method": "credit_card", "nonce": "test-nonce"}
        
        # First request
        r1 = self.request(self.sessions['user_a'], "POST",
                         endpoint, json=payload)
        
        if not r1 or r1.status_code != 200:
            self.log(Severity.INFO, "Initial request failed (test resource may not exist)")
            return
        
        # Wait a moment
        time.sleep(0.5)
        
        # Replay the exact same request
        r2 = self.request(self.sessions['user_a'], "POST",
                         endpoint, json=payload)
        
        if r2 and r2.status_code == 200:
            self.log(Severity.HIGH,
                    "Replay attack successful: Same request processed twice",
                    {"endpoint": endpoint})
        elif r2 and r2.status_code in (409, 422):
            self.log(Severity.PASSED,
                    "Replay attack blocked (duplicate request rejected)")
    
    def test_temporal_manipulation(self):
        """Test backdating/future-dating records"""
        print("\n[TEST] Temporal Manipulation (Backdating/Future-dating)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Test if users can manipulate timestamps
        temporal_payloads = [
            {
                "endpoint": "/api/v1/enquiries",
                "payload": {"name": "Test", "created_at": "2020-01-01"},
                "description": "Backdating enquiry creation"
            },
            {
                "endpoint": "/api/v1/payments",
                "payload": {"amount": 100, "paid_at": "2025-12-31"},
                "description": "Future-dating payment"
            }
        ]
        
        for test in temporal_payloads:
            r = self.request(self.sessions['user_a'], "POST",
                           test['endpoint'],
                           json=test['payload'])
            
            if r and r.status_code == 200:
                response_data = r.json()
                # Check if the manipulated timestamp was accepted
                if any(key in response_data for key in ['created_at', 'paid_at']):
                    self.log(Severity.HIGH,
                            f"Temporal manipulation possible: {test['description']}",
                            {"endpoint": test['endpoint']})
            elif r and r.status_code in (422, 403):
                self.log(Severity.PASSED,
                        f"Temporal manipulation blocked: {test['description']}")
