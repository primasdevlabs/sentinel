"""
Module 4: Business Logic & Workflow Integrity
Tests workflow state machines, business rules, concurrency, parameter tampering, and logic-level vulnerabilities
"""

try:
    from base_test import BaseSecurityTest, Severity
except ImportError:
    from sentinel.base_test import BaseSecurityTest, Severity
import time
import concurrent.futures


class BusinessLogicTests(BaseSecurityTest):
    """
    Business Logic & Workflow Integrity Security Test Suite
    
    Evaluates web applications and REST APIs against business logic vulnerabilities (CWE-840, OWASP API6:2023).
    Business logic flaws occur when application workflows, state machines, or domain rules can be bypassed,
    manipulated, or executed out of sequence by an attacker.
    """
    
    def run_tests(self):
        """Orchestrate and execute all business logic security tests"""
        print("\n" + "="*60)
        print("MODULE 4: BUSINESS LOGIC & WORKFLOW INTEGRITY")
        print("="*60)
        
        # Execute workflow transition & bypass tests
        self.test_status_skipping()
        self.test_role_invalid_transitions()
        self.test_state_reversal_and_downgrade()
        
        # Execute concurrency & transaction integrity tests
        self.test_race_conditions()
        self.test_replay_attacks()
        
        # Execute payload parameter & temporal manipulation tests
        self.test_temporal_manipulation()
        self.test_numeric_and_amount_tampering()
    
    def test_status_skipping(self):
        """
        Test Illegal Workflow Status Skipping (Workflow State Machine Bypass)
        
        Attack Vector:
        State machines mandate sequential transition flows (e.g. Order Pending -> Paid -> Processing -> Shipped).
        Attackers manipulate status parameters in PATCH/PUT requests to jump directly to late-stage states 
        (e.g., skipping payment or verification steps).
        
        Expected Result:
        The server MUST reject unauthorized status skips with 422 (Unprocessable Entity) or 403 (Forbidden).
        """
        print("\n[TEST] Status Skipping (Workflow State Machine Bypass)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Generic multi-domain enterprise workflow transition checks
        illegal_transitions = [
            {
                "endpoint": "/api/v1/orders/test-uuid",
                "payload": {"status": "shipped"},
                "description": "Order Lifecycle: Pending -> Shipped (skipping payment verification)"
            },
            {
                "endpoint": "/api/v1/users/test-uuid/status",
                "payload": {"status": "verified"},
                "description": "Identity Verification: Unverified -> Verified (skipping document/OTP check)"
            },
            {
                "endpoint": "/api/v1/invoices/test-uuid",
                "payload": {"status": "paid"},
                "description": "Financial Invoice: Draft -> Paid (skipping payment processing & approval)"
            },
            {
                "endpoint": "/api/v1/subscriptions/test-uuid",
                "payload": {"status": "active"},
                "description": "Subscription Flow: Trial Expired -> Active (skipping billing checkout)"
            }
        ]
        
        for transition in illegal_transitions:
            # Send state modification request as a standard user
            r = self.request(self.sessions['user_a'], "PATCH",
                           transition['endpoint'],
                           json=transition['payload'])
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Illegal workflow transition allowed: {transition['description']}",
                        {"endpoint": transition['endpoint'], "payload": transition['payload']})
            elif r and r.status_code in (403, 422):
                self.log(Severity.PASSED,
                        f"Workflow transition properly blocked: {transition['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Test endpoint/resource not found (expected): {transition['description']}")
    
    def test_role_invalid_transitions(self):
        """
        Test Role-Invalid Workflow Transitions (Privilege-Restricted Action Enforcement)
        
        Attack Vector:
        Certain workflow actions (e.g. approving invoices, granting admin roles, issuing refunds) 
        require elevated role permissions. Attackers invoke API endpoints directly to perform 
        administrative state changes using unprivileged credentials.
        
        Expected Result:
        The server MUST enforce role authorization checks and respond with HTTP 403 or 401.
        """
        print("\n[TEST] Role-Invalid Transitions (Restricted Action Execution)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Generic role-restricted administrative actions
        role_invalid_actions = [
            {
                "endpoint": "/api/v1/invoices/test-uuid/approve",
                "method": "POST",
                "payload": {"approved": True},
                "description": "Regular user approving high-value financial invoice (Manager/Admin-only action)"
            },
            {
                "endpoint": "/api/v1/users/me/role",
                "method": "PATCH",
                "payload": {"role": "admin"},
                "description": "Regular user attempting self-role elevation to Administrator"
            },
            {
                "endpoint": "/api/v1/payments/test-uuid/refund",
                "method": "POST",
                "payload": {"amount": 500.00},
                "description": "Regular user issuing arbitrary payment refund (Finance-only action)"
            },
            {
                "endpoint": "/api/v1/kyc/test-uuid/verify",
                "method": "POST",
                "payload": {"verified": True},
                "description": "Regular user self-verifying compliance/KYC status (Compliance-only action)"
            }
        ]
        
        for action in role_invalid_actions:
            r = self.request(self.sessions['user_a'],
                           action['method'],
                           action['endpoint'],
                           json=action.get('payload', {}))
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Role-invalid action allowed: {action['description']}",
                        {"endpoint": action['endpoint'], "method": action['method']})
            elif r and r.status_code in (403, 401):
                self.log(Severity.PASSED,
                        f"Role-invalid action properly blocked: {action['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Test endpoint not found (expected): {action['description']}")

    def test_state_reversal_and_downgrade(self):
        """
        Test Invalid Workflow State Reversal & Downgrade Attacks
        
        Attack Vector:
        Attempting to transition closed, fulfilled, or terminal resources back to earlier states 
        (e.g., reverting a completed order back to 'draft' to alter prices, or reactivating a canceled token).
        
        Expected Result:
        Terminal state transitions MUST be immutable and return 422 or 409 (Conflict).
        """
        print("\n[TEST] State Reversal & Terminal State Integrity")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        downgrade_attempts = [
            {
                "endpoint": "/api/v1/orders/completed-uuid",
                "payload": {"status": "draft"},
                "description": "Attempting to revert Completed order back to Draft"
            },
            {
                "endpoint": "/api/v1/auth/tokens/revoked-uuid",
                "payload": {"status": "active"},
                "description": "Attempting to reactivate a Revoked session token"
            }
        ]
        
        for attempt in downgrade_attempts:
            r = self.request(self.sessions['user_a'], "PATCH",
                           attempt['endpoint'],
                           json=attempt['payload'])
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"Terminal state downgrade allowed: {attempt['description']}",
                        {"endpoint": attempt['endpoint']})
            elif r and r.status_code in (403, 409, 422):
                self.log(Severity.PASSED,
                        f"Terminal state downgrade blocked: {attempt['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Resource not found (expected): {attempt['description']}")

    def test_race_conditions(self):
        """
        Test Race Conditions and Concurrency Exploits (Double Execution / Double Spend)
        
        Attack Vector:
        Issuing multiple identical concurrent requests within milliseconds to exploit time-of-check to 
        time-of-use (TOCTOU) race conditions in multi-threaded web application servers (e.g. redeeming 
        a single-use promo code twice, double-spending balance, double-claiming rewards).
        
        Expected Result:
        Only EXACTLY 1 request MUST succeed (200 OK); concurrent requests MUST return errors (409 Conflict, 422, or 429).
        """
        print("\n[TEST] Race Conditions (Concurrent Double Execution)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Target financial process endpoint susceptible to concurrency issues
        endpoint = "/api/v1/payments/test-uuid/process"
        payload = {"amount": 100.00, "currency": "USD", "method": "credit_card"}
        
        def make_request():
            try:
                return self.request(self.sessions['user_a'], "POST",
                                  endpoint, json=payload)
            except Exception:
                return None
        
        try:
            # Dispatch 5 simultaneous worker threads to hit the endpoint concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(make_request) for _ in range(5)]
                responses = [f.result(timeout=5) for f in futures]
            
            success_count = sum(1 for r in responses if r and r.status_code == 200)
            
            if success_count > 1:
                self.log(Severity.CRITICAL,
                        f"Race condition vulnerability: {success_count} concurrent requests succeeded",
                        {"endpoint": endpoint, "expected": 1, "actual": success_count})
            elif success_count == 1:
                self.log(Severity.PASSED,
                        "Race condition protection active (strictly 1 request succeeded)")
            elif success_count == 0:
                self.log(Severity.INFO,
                        "No requests succeeded (test endpoint/resource may not exist)")
        except (KeyboardInterrupt, Exception) as e:
            self.log(Severity.INFO,
                    f"Race condition test execution skipped: {type(e).__name__}")
    
    def test_replay_attacks(self):
        """
        Test Replay Attack Resistance (Idempotency and Nonce Validation)
        
        Attack Vector:
        Re-sending an identical, previously executed transaction request (e.g. repeating a payment, 
        coupon redemption, or approval action) to see if the server processes it a second time.
        
        Expected Result:
        Idempotent endpoints MUST reject replayed payloads using transaction nonces or deduplication keys (409/422).
        """
        print("\n[TEST] Replay Attack Resistance (Transaction Deduplication)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        endpoint = "/api/v1/transfers/test-uuid/execute"
        payload = {"amount": 100.00, "recipient_id": "user-b-uuid", "idempotency_key": "test-key-12345"}
        
        # Initial request
        r1 = self.request(self.sessions['user_a'], "POST",
                         endpoint, json=payload)
        
        if not r1 or r1.status_code != 200:
            self.log(Severity.INFO, "Initial request failed (test resource may not exist)")
            return
        
        # Short delay before replaying payload
        time.sleep(0.5)
        
        # Replay exact same request payload
        r2 = self.request(self.sessions['user_a'], "POST",
                         endpoint, json=payload)
        
        if r2 and r2.status_code == 200:
            self.log(Severity.HIGH,
                    "Replay attack successful: Duplicate transaction processed twice",
                    {"endpoint": endpoint, "idempotency_key": payload["idempotency_key"]})
        elif r2 and r2.status_code in (409, 422, 400):
            self.log(Severity.PASSED,
                    "Replay attack properly blocked (duplicate transaction rejected)")

    def test_numeric_and_amount_tampering(self):
        """
        Test Business Logic Numeric & Parameter Tampering
        
        Attack Vector:
        Injecting negative quantities, zero values, floating point rounding errors, or integer overflow 
        values into price, quantity, or balance fields to alter order totals or generate negative costs.
        
        Expected Result:
        The application MUST validate numeric boundaries and reject invalid values with 422 Unprocessable Entity.
        """
        print("\n[TEST] Numeric & Parameter Tampering (Negative Quantities / Zero Amounts)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        tampering_payloads = [
            {
                "endpoint": "/api/v1/cart/items",
                "payload": {"item_id": "item-123", "quantity": -5},
                "description": "Negative quantity injection in shopping cart"
            },
            {
                "endpoint": "/api/v1/orders/checkout",
                "payload": {"item_id": "item-123", "unit_price": 0.00, "quantity": 1},
                "description": "Zero-amount price manipulation during checkout"
            },
            {
                "endpoint": "/api/v1/payments/charge",
                "payload": {"amount": -100.00, "currency": "USD"},
                "description": "Negative payment amount injection"
            }
        ]
        
        for test in tampering_payloads:
            r = self.request(self.sessions['user_a'], "POST",
                           test['endpoint'],
                           json=test['payload'])
            
            if r and r.status_code == 200:
                self.log(Severity.CRITICAL,
                        f"Numeric parameter tampering vulnerability: {test['description']}",
                        {"endpoint": test['endpoint'], "payload": test['payload']})
            elif r and r.status_code in (400, 422, 403):
                self.log(Severity.PASSED,
                        f"Numeric parameter tampering properly blocked: {test['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Endpoint not found (expected): {test['description']}")

    def test_temporal_manipulation(self):
        """
        Test Temporal Manipulation (Backdating and Future-dating Audit Fields)
        
        Attack Vector:
        Supplying user-controlled timestamp parameters (e.g. created_at, paid_at, expires_at) 
        in API requests to backdate security logs or artificially extend trial subscription expiry dates.
        
        Expected Result:
        System audit fields MUST be calculated server-side; user-supplied timestamps MUST be ignored or rejected.
        """
        print("\n[TEST] Temporal Manipulation (Backdating / Future-Dating)")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        temporal_payloads = [
            {
                "endpoint": "/api/v1/records",
                "payload": {"title": "Test Record", "created_at": "2015-01-01T00:00:00Z"},
                "description": "Backdating record creation timestamp"
            },
            {
                "endpoint": "/api/v1/subscriptions",
                "payload": {"plan_id": "basic", "expires_at": "2099-12-31T23:59:59Z"},
                "description": "Future-dating subscription expiration timestamp"
            }
        ]
        
        for test in temporal_payloads:
            r = self.request(self.sessions['user_a'], "POST",
                           test['endpoint'],
                           json=test['payload'])
            
            if r and r.status_code == 200:
                response_data = r.json()
                # Verify if server accepted the client-supplied timestamp
                if any(response_data.get(k) == test['payload'].get(k) for k in ['created_at', 'expires_at']):
                    self.log(Severity.HIGH,
                            f"Temporal manipulation vulnerability: {test['description']}",
                            {"endpoint": test['endpoint'], "payload": test['payload']})
                else:
                    self.log(Severity.PASSED,
                            f"Server overrode client-supplied timestamp: {test['description']}")
            elif r and r.status_code in (422, 403, 400):
                self.log(Severity.PASSED,
                        f"Temporal manipulation properly blocked: {test['description']}")
            elif r and r.status_code == 404:
                self.log(Severity.INFO,
                        f"Endpoint not found (expected): {test['description']}")
