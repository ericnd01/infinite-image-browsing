#!/usr/bin/env python3
"""
Local helper agent for "Open with Local File Browser" in infinite-image-browsing.

Runs on your Mac (127.0.0.1 only) and reveals a path in Finder when asked.
This lets the browser-based app trigger Finder directly, instead of only
copying the resolved local path to your clipboard.

Usage:
    python3 finder_agent.py [--port 8765] [--token TOKEN]

On first run it generates and saves a random token to
~/.iib_finder_agent_token and prints it. Put the printed URL and token
into the app's Settings > Remote Mount > Local Open Agent fields.

Security: the agent only binds to 127.0.0.1 (never reachable from the
network) and every request must include the matching token, so a random
website you visit cannot use it even though it responds to cross-origin
requests.
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

TOKEN_FILE = Path.home() / ".iib_finder_agent_token"


def load_or_create_token() -> str:
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)
    return token


def make_handler(token: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _cors_headers(self):
            origin = self.headers.get("Origin", "*")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            # Chrome's Private Network Access check: required for a page on
            # another host/port to fetch a 127.0.0.1 endpoint.
            self.send_header("Access-Control-Allow-Private-Network", "true")

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors_headers()
            self.end_headers()

        def _json(self, status: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self._cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            if parsed.path == "/health":
                self._json(200, {"ok": True})
                return

            if parsed.path != "/open":
                self._json(404, {"ok": False, "error": "not found"})
                return

            req_token = (qs.get("token") or [""])[0]
            if not secrets.compare_digest(req_token, token):
                self._json(403, {"ok": False, "error": "bad token"})
                return

            raw_path = (qs.get("path") or [""])[0]
            path = unquote(raw_path)
            if not path:
                self._json(400, {"ok": False, "error": "missing path"})
                return

            if not os.path.exists(path):
                self._json(404, {"ok": False, "error": f"path does not exist on this Mac: {path}"})
                return

            try:
                if os.path.isdir(path):
                    subprocess.run(["open", path], check=True)
                else:
                    subprocess.run(["open", "-R", path], check=True)  # reveal + select in Finder
                    subprocess.run(["open", path], check=True)  # launch with the default app
            except subprocess.CalledProcessError as e:
                self._json(500, {"ok": False, "error": str(e)})
                return

            self._json(200, {"ok": True, "opened": path})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default=None, help="Use a fixed token instead of the saved/generated one")
    args = parser.parse_args()

    token = args.token or load_or_create_token()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(token))
    url = f"http://127.0.0.1:{args.port}"
    print(f"Finder agent listening on {url}")
    print(f"Token: {token}")
    print()
    print("In the app: Settings > Remote Mount > Local Open Agent")
    print(f"  Agent URL:   {url}")
    print(f"  Agent Token: {token}")
    print()
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
