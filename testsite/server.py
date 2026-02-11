#!/usr/bin/env python3
"""Minimal test server for JSBot detection testing.

Usage: python testsite/server.py [port]
Default port: 8777
"""
import sys
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def log_message(self, format, *args):
        pass  # suppress logs

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8777
print(f"Test site running at http://localhost:{port}")
HTTPServer(("127.0.0.1", port), Handler).serve_forever()
