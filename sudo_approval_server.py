#!/usr/bin/env python3
"""Minimal HTTP service for the request-bound sudo approval verifier."""
from __future__ import annotations

import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from api.helpers import j, t
from api.sudo_approval_routes import (
    handle_sudo_approval_get,
    handle_sudo_approval_post,
)
from api.sudo_approvals import (
    ApprovalVerifier,
    SudoApprovalConfigError,
    SudoApprovalError,
    configured_verifier,
    validate_request_host,
)


_MAX_BODY_BYTES = 256 * 1024
_STATIC_ROOT = (Path(__file__).resolve().parent / "static").resolve()
_STATIC_FILES = {
    "/static/sudo-approval.css": ("sudo-approval.css", "text/css; charset=utf-8"),
    "/static/sudo-approval.js": (
        "sudo-approval.js",
        "application/javascript; charset=utf-8",
    ),
}


def _not_found(handler) -> None:
    j(handler, {"error": "not found"}, status=404, pretty=False)


def _validate_static_host(handler, verifier: ApprovalVerifier) -> bool:
    try:
        validate_request_host(handler, verifier)
    except SudoApprovalError:
        _not_found(handler)
        return False
    return True


def _runtime_verifier(handler) -> ApprovalVerifier | None:
    try:
        verifier = configured_verifier()
        verifier.validate_runtime_boundary()
        return verifier
    except SudoApprovalError:
        j(
            handler,
            {"error": "sudo approval is unavailable"},
            status=503,
            pretty=False,
        )
        return None


class VerifierHandler(BaseHTTPRequestHandler):
    """Closed verifier-only surface; every unmatched route is a narrow 404."""

    protocol_version = "HTTP/1.1"
    timeout = 15
    server_version = "HermesSudoVerifier/1"

    def log_message(self, _format: str, *_args) -> None:
        # Request paths carry one-time capabilities. Never place them in logs.
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            verifier = _runtime_verifier(self)
            if verifier is None:
                return
            return j(
                self,
                {
                    "status": "ok",
                    "service": "sudo-approval-verifier",
                    "mode": "verifier",
                },
                pretty=False,
            )
        verifier = _runtime_verifier(self)
        if verifier is None:
            return
        static = _STATIC_FILES.get(parsed.path)
        if static is not None:
            if not _validate_static_host(self, verifier):
                return
            filename, content_type = static
            return t(
                self,
                (_STATIC_ROOT / filename).read_bytes(),
                content_type=content_type,
                extra_headers={
                    "Referrer-Policy": "no-referrer",
                    "X-Robots-Tag": "noindex, nofollow",
                },
            )
        result = handle_sudo_approval_get(self, parsed)
        if result is False:
            _not_found(self)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if _runtime_verifier(self) is None:
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return j(self, {"error": "invalid content length"}, status=400, pretty=False)
        if not 0 <= content_length <= _MAX_BODY_BYTES:
            return j(self, {"error": "request body is too large"}, status=413, pretty=False)
        if self.headers.get_content_type() != "application/json":
            return j(self, {"error": "application/json is required"}, status=415, pretty=False)
        try:
            body = json.loads(self.rfile.read(content_length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return j(self, {"error": "invalid JSON"}, status=400, pretty=False)
        if not isinstance(body, dict):
            return j(self, {"error": "JSON object is required"}, status=400, pretty=False)
        result = handle_sudo_approval_post(self, parsed, body)
        if result is False:
            _not_found(self)

    def do_OPTIONS(self) -> None:
        _not_found(self)

    def do_PUT(self) -> None:
        _not_found(self)

    def do_PATCH(self) -> None:
        _not_found(self)

    def do_DELETE(self) -> None:
        _not_found(self)


def validate_startup() -> ApprovalVerifier:
    if os.getenv("HERMES_WEBUI_SERVICE_MODE", "").strip() != "verifier":
        raise SudoApprovalConfigError(
            "sudo approval entrypoint requires HERMES_WEBUI_SERVICE_MODE=verifier"
        )
    verifier = configured_verifier()
    verifier.validate_runtime_boundary()
    return verifier


def main() -> int:
    try:
        validate_startup()
        host = os.getenv("HERMES_WEBUI_HOST", "127.0.0.1").strip()
        port = int(os.getenv("HERMES_WEBUI_PORT", "8788"))
        if not host or not 1 <= port <= 65535:
            raise SudoApprovalConfigError("sudo approval listener is invalid")
    except (ValueError, SudoApprovalError) as exc:
        print(f"sudo approval verifier startup refused: {exc}", flush=True)
        return 1

    server = ThreadingHTTPServer((host, port), VerifierHandler)
    server.daemon_threads = True
    shutting_down = threading.Event()

    def stop(_signum, _frame) -> None:
        if shutting_down.is_set():
            return
        shutting_down.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
