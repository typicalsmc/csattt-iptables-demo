#!/usr/bin/env python3
"""
Simple HTTP server for the iptables demo.
Logs every request with timestamp and client IP.
"""

import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 80

BOLD  = "\033[1m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RESET = "\033[0m"


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        body = json.dumps({
            "status": "ok",
            "message": "Hello from the iptables demo server!",
            "path": self.path,
            "client": client_ip,
            "time": ts,
        }, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Demo", "iptables-firewall")
        self.end_headers()
        self.wfile.write(body)

        print(
            f"{GREEN}[{ts}] GET {self.path!r:<20} "
            f"← {BOLD}{client_ip}{RESET}{GREEN} — 200 OK{RESET}",
            flush=True,
        )

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def log_message(self, fmt, *args):
        # suppress default noisy access log — we handle it in do_GET
        pass


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), DemoHandler)
    print(
        f"\n{CYAN}{BOLD}[SERVER]{RESET} HTTP server listening on "
        f"{BOLD}{HOST}:{PORT}{RESET}",
        flush=True,
    )
    print(
        f"{CYAN}{BOLD}[SERVER]{RESET} "
        "Waiting for connections (only valid packets will reach here)...\n",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
        server.server_close()
