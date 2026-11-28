"""ARKHEIA Mandate / Aegis-Swarm — standalone sidecar (stdlib only).

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

    python -m arkheia_clearance.server --host 127.0.0.1 --port 8090

Holds its own signing key (see ``service.engine_from_env``), so the CPS
backend can stay verify-only and proxy to this process if preferred.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import ClearanceService, engine_from_env, floor_ns_from_env

MAX_READ = 1 << 20


def make_handler(service: ClearanceService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ARKHEIA-Clearance/1.0"
        sys_version = ""

        def _serve(self, method: str) -> None:
            length_hdr = self.headers.get("Content-Length", "0").strip()
            length = int(length_hdr) if length_hdr.isdigit() else -1
            if length < 0 or length > MAX_READ:
                body = b"\x00" * (service.engine.policy.max_body_bytes + 1) if service.engine else b""
                self.close_connection = True
            else:
                body = self.rfile.read(length) if length else b""
            headers = {k.lower(): v for k, v in self.headers.items()}
            status, out_headers, payload = service.dispatch(method, self.path, body, headers)
            self.send_response(status)
            for k, v in out_headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def do_GET(self) -> None:  # noqa: N802
            self._serve("GET")

        def log_message(self, fmt: str, *args) -> None:  # request bodies/headers are never logged
            return

    return Handler


def build_server(service: ClearanceService, host: str = "127.0.0.1", port: int = 8090) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(service))


def main() -> None:
    ap = argparse.ArgumentParser(description="ARKHEIA Mandate / Aegis-Swarm clearance sidecar")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()
    service = ClearanceService(engine_from_env(), floor_ns_from_env())
    srv = build_server(service, args.host, args.port)
    print(f"arkheia-clearance listening on {args.host}:{args.port} key={service.engine.public_key_id}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
