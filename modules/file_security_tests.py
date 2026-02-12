"""
Module 5: File & Document Security
Tests file upload validation, storage security, and document handling
"""

from pentest.base_test import BaseSecurityTest, Severity
import io


class FileSecurityTests(BaseSecurityTest):
    """File & Document Security Tests"""
    
    def run_tests(self):
        """Run all file security tests"""
        print("\n" + "="*60)
        print("MODULE 5: FILE & DOCUMENT SECURITY")
        print("="*60)
        
        self.test_double_extension_upload()
        self.test_mime_type_validation()
        self.test_mime_spoofing()
        self.test_path_traversal()
        self.test_direct_file_access()
        self.test_presigned_url_expiry()
    
    def test_double_extension_upload(self):
        """Test double extension file upload (.php.png)"""
        print("\n[TEST] Double Extension Upload")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        malicious_files = [
            ('shell.php.png', '<?php echo "vulnerable"; ?>', 'image/png'),
            ('backdoor.asp.jpg', '<%eval request("cmd")%>', 'image/jpeg'),
            ('exploit.jsp.gif', '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>', 'image/gif')
        ]
        
        upload_endpoints = [
            "/api/v1/documents/upload",
            "/api/v1/admissions/test-uuid/documents",
            "/api/v1/students/test-uuid/documents"
        ]
        
        for endpoint in upload_endpoints:
            for filename, content, mime_type in malicious_files:
                files = {'document': (filename, content, mime_type)}
                data = {'name': 'Security Test', 'type': 'other'}
                
                r = self.request(self.sessions['user_a'], "POST",
                               endpoint, files=files, data=data)
                
                if r and r.status_code == 200:
                    self.log(Severity.CRITICAL,
                            f"Double extension upload allowed: {filename}",
                            {"endpoint": endpoint, "filename": filename})
                    break
                elif r and r.status_code in (403, 422):
                    self.log(Severity.PASSED,
                            f"Double extension upload blocked: {filename}")
                    break
    
    def test_mime_type_validation(self):
        """Test MIME type validation"""
        print("\n[TEST] MIME Type Validation")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # Try uploading executable with wrong MIME type
        files = {
            'document': ('test.exe', b'MZ\x90\x00', 'image/png')  # EXE magic bytes with PNG MIME
        }
        
        r = self.request(self.sessions['user_a'], "POST",
                       "/api/v1/documents/upload",
                       files=files,
                       data={'name': 'Test', 'type': 'other'})
        
        if r and r.status_code == 200:
            self.log(Severity.HIGH,
                    "MIME type validation bypassed (executable uploaded as image)")
        elif r and r.status_code in (422, 403):
            self.log(Severity.PASSED, "MIME type validation active")
    
    def test_mime_spoofing(self):
        """Test MIME spoofing detection"""
        print("\n[TEST] MIME Spoofing Detection")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        # PHP code with PNG header
        spoofed_content = b'\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>'
        
        files = {'document': ('image.png', spoofed_content, 'image/png')}
        
        r = self.request(self.sessions['user_a'], "POST",
                       "/api/v1/documents/upload",
                       files=files,
                       data={'name': 'Spoofed', 'type': 'image'})
        
        if r and r.status_code == 200:
            self.log(Severity.HIGH,
                    "MIME spoofing possible (PHP code in PNG file)")
        elif r and r.status_code in (422, 403):
            self.log(Severity.PASSED, "MIME spoofing detected and blocked")
    
    def test_path_traversal(self):
        """Test path traversal in file operations"""
        print("\n[TEST] Path Traversal")
        
        if not self.sessions['user_a'].cookies.get('laravel_session'):
            self.log(Severity.INFO, "Skipping: No user_a session configured")
            return
        
        traversal_payloads = [
            "../../.env",
            "../../../config/app.php",
            "..\\..\\..\\storage\\logs\\laravel.log",
            "/etc/passwd"
        ]
        
        for payload in traversal_payloads:
            r = self.request(self.sessions['user_a'], "GET",
                           f"/api/v1/documents/{payload}")
            
            if r and r.status_code == 200:
                if ".env" in r.text or "APP_KEY" in r.text or "root:" in r.text:
                    self.log(Severity.CRITICAL,
                            f"Path traversal successful: {payload}",
                            {"payload": payload})
                    break
        else:
            self.log(Severity.PASSED, "Path traversal attacks blocked")
    
    def test_direct_file_access(self):
        """Test direct file access bypass"""
        print("\n[TEST] Direct File Access")
        
        # Test if files can be accessed directly without authentication
        file_paths = [
            "/storage/documents/test.pdf",
            "/uploads/documents/test.pdf",
            "/public/uploads/test.pdf"
        ]
        
        session = self.sessions['unauthenticated']
        
        for path in file_paths:
            r = self.request(session, "GET", path, allow_redirects=False)
            
            if r and r.status_code == 200:
                self.log(Severity.HIGH,
                        f"Direct file access possible: {path}",
                        {"path": path})
            elif r and r.status_code in (403, 404):
                self.log(Severity.PASSED, f"Direct file access blocked: {path}")
    
    def test_presigned_url_expiry(self):
        """Test pre-signed URL expiry enforcement"""
        print("\n[TEST] Pre-signed URL Expiry")
        
        self.log(Severity.INFO,
                "Pre-signed URL test requires generating and waiting for expiry")
        self.log(Severity.INFO,
                "Manual verification: Generate pre-signed URL → Wait for expiry → Try accessing")
