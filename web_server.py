"""
Sentinel-12 Security Protocol - Web UI Server
Launches the built React dashboard interface and local API proxy
"""

import http.server
import socketserver
import os
import sys
import mimetypes
import webbrowser

DEFAULT_PORT = 8080
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), 'frontend', 'dist')

# Ensure correct MIME types on Windows platforms
mimetypes.init()
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('application/javascript', '.mjs')
mimetypes.add_type('text/css', '.css')
mimetypes.add_type('image/svg+xml', '.svg')
mimetypes.add_type('application/json', '.json')

class SentinelUIHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        '': 'application/octet-stream',
        '.html': 'text/html; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.mjs': 'application/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIST, **kwargs)

    def do_GET(self):
        # Fallback to index.html for SPA routes if requested path is not a physical file
        req_path = self.translate_path(self.path)
        if not os.path.exists(req_path) and not os.path.splitext(req_path)[1]:
            self.path = '/index.html'
        return super().do_GET()

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def find_available_server(start_port=8080, max_attempts=20):
    for port in range(start_port, start_port + max_attempts):
        try:
            httpd = ReusableTCPServer(("", port), SentinelUIHandler)
            return httpd, port
        except OSError:
            continue
    return None, None

def run_server():
    if not os.path.exists(FRONTEND_DIST):
        print(f"Error: Build directory not found at {FRONTEND_DIST}")
        print("Please build the frontend first:")
        print("  cd frontend && npm install && npm run build")
        sys.exit(1)

    httpd, port = find_available_server(DEFAULT_PORT)
    if not httpd:
        print(f"Error: Could not find an open port starting from {DEFAULT_PORT}.")
        sys.exit(1)

    print("=" * 60)
    print("🔒 SENTINEL-12 // DEFCON 1 SITUATION ROOM WEB DASHBOARD")
    print("=" * 60)
    print(f"Server listening at: http://localhost:{port}")
    print("Press Ctrl+C to stop the server.")
    print("=" * 60)

    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down situation room web server.")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
