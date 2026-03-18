#!/usr/bin/env python3
"""
Simple HTTP server for the iptables demo.
Logs every request with timestamp and client IP.

Endpoints:
  GET /              — health check / echo
  GET /ipset/<name>  — list members of a named ipset (for test verification)
"""

import json
import os
import re
import subprocess
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "0.0.0.0"
PORT = 80

BOLD  = "\033[1m"
GREEN = "\033[92m"
CYAN  = "\033[96m"
RED   = "\033[91m"
RESET = "\033[0m"

# Allowed ipset names — alphanumeric and hyphens only.
_SETNAME_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,30}$')


def _query_ipset(setname: str) -> dict:
    """Return members and header info for a named ipset."""
    if not _SETNAME_RE.match(setname):
        return {"error": "invalid set name"}
    try:
        out = subprocess.run(
            ["ipset", "list", setname],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return {"error": f"ipset not found: {setname}"}

        members = []
        in_members = False
        header = {}
        for line in out.stdout.splitlines():
            if line.startswith("Members:"):
                in_members = True
                continue
            if in_members:
                entry = line.strip()
                if entry:
                    # Strip timeout annotation if present ("1.2.3.4 timeout 100")
                    members.append(entry.split()[0])
            elif ":" in line:
                key, _, val = line.partition(":")
                header[key.strip().lower().replace(" ", "_")] = val.strip()

        return {
            "set": setname,
            "header": header,
            "members": members,
            "count": len(members),
        }
    except FileNotFoundError:
        return {"error": "ipset not available"}
    except subprocess.TimeoutExpired:
        return {"error": "ipset command timed out"}


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # ── /ipset/<name> ──────────────────────────────────────────
        if self.path.startswith("/ipset/"):
            setname = self.path[len("/ipset/"):].strip("/")
            data = _query_ipset(setname)
            status = 404 if "error" in data else 200
            self._send_json(data, status, ts, client_ip)
            return

        # ── / (default) ────────────────────────────────────────────
        body_data = {
            "status": "ok",
            "message": "Hello from the iptables demo server!",
            "path": self.path,
            "client": client_ip,
            "time": ts,
        }
        self._send_json(body_data, 200, ts, client_ip)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def _send_json(self, data: dict, status: int, ts: str, client_ip: str) -> None:
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Demo", "iptables-firewall")
        self.end_headers()
        self.wfile.write(body)

        colour = GREEN if status == 200 else RED
        print(
            f"{colour}[{ts}] GET {self.path!r:<28} "
            f"← {BOLD}{client_ip}{RESET}{colour} — {status}{RESET}",
            flush=True,
        )

    def log_message(self, fmt, *args):
        pass  # suppress default noisy access log


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
