"""HTTP adapters for the isolated sudo approval verifier."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from api.helpers import j, t
from api.sudo_approvals import (
    SudoApprovalConfigError,
    SudoApprovalConflict,
    SudoApprovalError,
    SudoApprovalExpired,
    SudoApprovalUnauthorized,
    configured_verifier,
    validate_browser_origin,
    validate_request_host,
)


_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_PAGE_PATH = (Path(__file__).parent.parent / "static" / "sudo-approval.html").resolve()


def _capability(path: str, prefix: str) -> str | None:
    if not path.startswith(prefix):
        return None
    value = path[len(prefix) :]
    if "/" in value or not _CAPABILITY_RE.fullmatch(value):
        return None
    return value


def _error_response(handler, exc: SudoApprovalError):
    if isinstance(exc, SudoApprovalConfigError):
        return j(handler, {"error": "sudo approval is unavailable"}, status=404)
    if isinstance(exc, SudoApprovalExpired):
        return j(handler, {"error": str(exc)}, status=410)
    if isinstance(exc, SudoApprovalConflict):
        return j(handler, {"error": str(exc)}, status=409)
    if isinstance(exc, SudoApprovalUnauthorized):
        return j(handler, {"error": str(exc)}, status=403)
    return j(handler, {"error": str(exc)}, status=400)


def handle_sudo_approval_get(handler, parsed) -> bool:
    """Serve sessionless approval/enrollment pages and their exact records."""
    page_kind = None
    capability = _capability(parsed.path, "/sudo-approval/")
    if capability is not None:
        page_kind = "approval"
    else:
        capability = _capability(parsed.path, "/sudo-enrollment/")
        if capability is not None:
            page_kind = "enrollment"

    request_nonce = _capability(parsed.path, "/api/sudo-approval/requests/")
    enrollment_token = _capability(parsed.path, "/api/sudo-approval/enrollments/")
    if page_kind is None and request_nonce is None and enrollment_token is None:
        return False

    try:
        verifier = configured_verifier()
        validate_request_host(handler, verifier)
        if page_kind is not None:
            html = _PAGE_PATH.read_text(encoding="utf-8")
            return t(
                handler,
                html,
                content_type="text/html; charset=utf-8",
                extra_headers={
                    "Referrer-Policy": "no-referrer",
                    "X-Robots-Tag": "noindex, nofollow",
                },
            )
        if request_nonce is not None:
            return j(handler, {"request": verifier.request_status(request_nonce)})
        return j(
            handler,
            {"enrollment": verifier.enrollment_status(enrollment_token or "")},
        )
    except SudoApprovalError as exc:
        _error_response(handler, exc)
        return True


def handle_sudo_approval_post(handler, parsed, body: dict[str, Any]) -> bool:
    """Handle only browser-facing, sessionless WebAuthn state transitions."""
    actions = {
        "/api/sudo-approval/options",
        "/api/sudo-approval/approve",
        "/api/sudo-approval/deny",
        "/api/sudo-approval/enrollment/options",
        "/api/sudo-approval/enrollment/finish",
    }
    if parsed.path not in actions:
        return False
    try:
        verifier = configured_verifier()
        validate_browser_origin(handler, verifier)
        if parsed.path == "/api/sudo-approval/options":
            return j(
                handler,
                {"publicKey": verifier.approval_options(str(body.get("nonce") or ""))},
            )
        if parsed.path == "/api/sudo-approval/approve":
            nonce = str(body.get("nonce") or "")
            return j(handler, {"request": verifier.approve(nonce, body)})
        if parsed.path == "/api/sudo-approval/deny":
            return j(
                handler,
                {"request": verifier.deny(str(body.get("nonce") or ""))},
            )
        if parsed.path == "/api/sudo-approval/enrollment/options":
            return j(
                handler,
                {
                    "publicKey": verifier.enrollment_options(
                        str(body.get("token") or "")
                    )
                },
            )
        return j(
            handler,
            {
                "result": verifier.finish_enrollment(
                    str(body.get("token") or ""),
                    body,
                )
            },
        )
    except SudoApprovalError as exc:
        _error_response(handler, exc)
        return True
