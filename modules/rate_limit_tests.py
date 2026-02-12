"""
Module 7: Rate Limiting & Abuse Controls
Tests rate limiting, throttling, and abuse prevention mechanisms
"""

from sentinel.base_test import BaseSecurityTest, Severity
import time


class RateLimitTests(BaseSecurityTest):
    """Rate Limiting & Abuse Control Tests"""
    
    def run_tests(self):
        """Run all rate limiting tests"""
        print("\n" + "="*60)
        print("MODULE 7: RATE LIMITING & ABUSE CONTROLS")
        print("="*60)
        
        self.test_api_rate_limiting()
        self.test_login_rate_limiting()
        self.test_per_ip_vs_per_user_limits()
    
    def test_api_rate_limiting(self):
        """Test API rate limiting"""
        print("\n[TEST] API Rate Limiting")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        endpoint = "/api/v1/users/me"
        rate_limit_hit = False
        
        for i in range(100):
            r = self.request(self.sessions['user_a'], "GET", endpoint)
            
            if r and r.status_code == 429:
                self.log(Severity.PASSED,
                        f"Rate limiting active (429 after {i+1} requests)")
                rate_limit_hit = True
                break
            
            time.sleep(0.1)
        
        if not rate_limit_hit:
            self.log(Severity.MEDIUM,
                    "No rate limiting detected after 100 requests")
    
    def test_login_rate_limiting(self):
        """Test login rate limiting"""
        print("\n[TEST] Login Rate Limiting")
        
        login_endpoint = "/portal/auth/login"
        
        for i in range(10):
            r = self.request(self.sessions['unauthenticated'], "POST",
                           login_endpoint,
                           json={"email": "test@test.com", "password": "wrong"})
            
            if r and r.status_code == 429:
                self.log(Severity.PASSED,
                        f"Login rate limiting active (429 after {i+1} attempts)")
                return
            
            time.sleep(0.5)
        
        self.log(Severity.HIGH,
                "No login rate limiting detected after 10 failed attempts")
    
    def test_per_ip_vs_per_user_limits(self):
        """Test per-IP vs per-user rate limits"""
        print("\n[TEST] Per-IP vs Per-User Limits")
        
        self.log(Severity.INFO,
                "Per-IP vs per-user test requires multiple IP addresses")
        self.log(Severity.INFO,
                "Manual verification: Hit rate limit → Change IP → Verify if limit persists")
