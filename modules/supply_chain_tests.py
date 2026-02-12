"""
Module 10: Supply Chain & Dependency Risk
Tests dependency security and supply chain integrity
"""

from sentinel.base_test import BaseSecurityTest, Severity
import subprocess


class SupplyChainTests(BaseSecurityTest):
    """Supply Chain & Dependency Risk Tests"""
    
    def run_tests(self):
        """Run all supply chain tests"""
        print("\n" + "="*60)
        print("MODULE 10: SUPPLY CHAIN & DEPENDENCY RISK")
        print("="*60)
        
        self.test_composer_audit()
        self.test_abandoned_packages()
    
    def test_composer_audit(self):
        """Test for known vulnerabilities in dependencies"""
        print("\n[TEST] Composer Audit")
        
        try:
            result = subprocess.run(['composer', 'audit'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=30)
            
            if "No security vulnerability advisories found" in result.stdout:
                self.log(Severity.PASSED, "No known vulnerabilities in dependencies")
            else:
                self.log(Severity.HIGH,
                        "Vulnerabilities found in dependencies",
                        {"output": result.stdout[:500]})
        except Exception as e:
            self.log(Severity.INFO,
                    f"Could not run composer audit: {e}")
    
    def test_abandoned_packages(self):
        """Test for abandoned packages"""
        print("\n[TEST] Abandoned Packages")
        
        self.log(Severity.INFO,
                "Abandoned package detection requires composer.lock analysis")
        self.log(Severity.INFO,
                "Manual verification: Run 'composer outdated' and check for abandoned packages")
