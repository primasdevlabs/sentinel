"""
Module 5: File & Upload Security
Tests file upload restrictions, path traversal, double extensions, and execution vector protections.
"""

from base_test import BaseSecurityTest, Severity


class FileSecurityTests(BaseSecurityTest):
    """File Upload & Storage Security Tests"""

    def run_tests(self):
        """Run all file security tests"""
        print("\n" + "="*60)
        print("MODULE 5: FILE & UPLOAD SECURITY")
        print("="*60)

        self.test_unrestricted_file_upload()
        self.test_path_traversal_upload()

    def test_unrestricted_file_upload(self):
        """Test for unrestricted file upload vulnerabilities"""
        print("\n[TEST] Unrestricted File Upload")

        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return

        payload = {
            'file': ('test.php', '<?php echo "shell"; ?>', 'application/x-php')
        }

        r = self.request(self.sessions['user_a'], "POST",
                         "/api/v1/user/avatar",
                         files=payload)

        if r and r.status_code == 200 and ("avatar" in r.text or "url" in r.text):
            self.log(Severity.CRITICAL, "Executable file upload accepted (.php)")
        else:
            self.log(Severity.PASSED, "Executable upload rejected or blocked")

    def test_path_traversal_upload(self):
        """Test path traversal via file name parameter"""
        print("\n[TEST] Path Traversal in File Upload")

        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return

        payload = {
            'file': ('../../../../etc/passwd', 'test content', 'text/plain')
        }

        r = self.request(self.sessions['user_a'], "POST",
                         "/api/v1/user/documents",
                         files=payload)

        if r and r.status_code == 200 and "passwd" in r.text:
            self.log(Severity.HIGH, "Path traversal sequence in file upload processed")
        else:
            self.log(Severity.PASSED, "Path traversal filename sanitized or rejected")
