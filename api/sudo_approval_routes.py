"""HTTP adapters for the isolated sudo approval verifier."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from api.helpers import j, t
from api.sudo_approvals import (
    SudoApprovalConfigError,
    SudoApprovalConflict,
    SudoApprovalError,
    SudoApprovalExpired,
    SudoApprovalUnauthorized,
    configured_verifier,
    validate_broker_authorization,
    validate_browser_origin,
    validate_request_host,
)


_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_UUID_PATTERN = (
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_APPROVAL_PAGE_RE = re.compile(
    rf"^/sudo-approval/(?P<request_id>{_UUID_PATTERN})/"
    r"(?P<url_token>[A-Za-z0-9_-]{43})$"
)
_APPROVAL_RECORD_RE = re.compile(
    rf"^/api/sudo-approval/requests/(?P<request_id>{_UUID_PATTERN})/"
    r"(?P<url_token>[A-Za-z0-9_-]{43})$"
)
_BROKER_DECISION_RE = re.compile(
    rf"^/api/sudo-approval/broker/v1/requests/(?P<request_id>{_UUID_PATTERN})/decision$"
)
_BROKER_CONSUME_RE = re.compile(
    rf"^/api/sudo-approval/broker/v1/requests/(?P<request_id>{_UUID_PATTERN})/consume$"
)
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


def _approval_page(handler) -> bool:
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


def handle_sudo_approval_get(handler, parsed) -> bool:
    """Serve browser capabilities and broker-authenticated decision status."""
    approval_page = _APPROVAL_PAGE_RE.fullmatch(parsed.path)
    approval_record = _APPROVAL_RECORD_RE.fullmatch(parsed.path)
    enrollment_token = _capability(parsed.path, "/sudo-enrollment/")
    enrollment_record = _capability(
        parsed.path,
        "/api/sudo-approval/enrollments/",
    )
    broker_decision = _BROKER_DECISION_RE.fullmatch(parsed.path)
    if not any(
        (
            approval_page,
            approval_record,
            enrollment_token,
            enrollment_record,
            broker_decision,
        )
    ):
        return False

    try:
        verifier = configured_verifier()
        validate_request_host(handler, verifier)
        if broker_decision is not None:
            validate_broker_authorization(handler, verifier)
            wait_values = parse_qs(parsed.query).get("wait", ["0"])
            try:
                wait_seconds = int(wait_values[0])
            except (TypeError, ValueError) as exc:
                raise SudoApprovalError("wait must be an integer") from exc
            if not 0 <= wait_seconds <= 10:
                raise SudoApprovalError("wait must be between 0 and 10 seconds")
            deadline = time.monotonic() + wait_seconds
            decision = verifier.decision_status(
                broker_decision.group("request_id")
            )
            while (
                decision["status"] == "pending"
                and time.monotonic() < deadline
            ):
                time.sleep(min(0.2, deadline - time.monotonic()))
                decision = verifier.decision_status(
                    broker_decision.group("request_id")
                )
            return j(
                handler,
                decision,
            )
        if approval_page is not None or enrollment_token is not None:
            return _approval_page(handler)
        if approval_record is not None:
            return j(
                handler,
                {
                    "request": verifier.request_status(
                        approval_record.group("request_id"),
                        approval_record.group("url_token"),
                    )
                },
            )
        return j(
            handler,
            {"enrollment": verifier.enrollment_status(enrollment_record or "")},
        )
    except SudoApprovalError as exc:
        _error_response(handler, exc)
        return True


def handle_sudo_approval_post(handler, parsed, body: dict[str, Any]) -> bool:
    """Handle broker transport and browser-facing WebAuthn transitions."""
    broker_create = parsed.path == "/api/sudo-approval/broker/v1/requests"
    broker_consume = _BROKER_CONSUME_RE.fullmatch(parsed.path)
    browser_actions = {
        "/api/sudo-approval/options",
        "/api/sudo-approval/approve",
        "/api/sudo-approval/deny",
        "/api/sudo-approval/enrollment/options",
        "/api/sudo-approval/enrollment/finish",
    }
    if not broker_create and broker_consume is None and parsed.path not in browser_actions:
        return False
    try:
        verifier = configured_verifier()
        validate_request_host(handler, verifier)
        if broker_create or broker_consume is not None:
            validate_broker_authorization(handler, verifier)
            if broker_create:
                return j(handler, verifier.register_request(body), status=201)
            request_id = broker_consume.group("request_id")
            result = verifier.consume_approval(
                request_id=request_id,
                request=body.get("request"),
                request_digest=body.get("request_digest"),
                decision_id=body.get("decision_id"),
            )
            return j(handler, result)

        validate_browser_origin(handler, verifier)
        if parsed.path == "/api/sudo-approval/options":
            return j(
                handler,
                {
                    "publicKey": verifier.approval_options(
                        str(body.get("request_id") or ""),
                        str(body.get("url_token") or ""),
                    )
                },
            )
        if parsed.path == "/api/sudo-approval/approve":
            return j(
                handler,
                {
                    "request": verifier.approve(
                        str(body.get("request_id") or ""),
                        str(body.get("url_token") or ""),
                        body,
                    )
                },
            )
        if parsed.path == "/api/sudo-approval/deny":
            return j(
                handler,
                {
                    "request": verifier.deny(
                        str(body.get("request_id") or ""),
                        str(body.get("url_token") or ""),
                    )
                },
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
