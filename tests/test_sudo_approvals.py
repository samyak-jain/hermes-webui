"""Security contract tests for request-bound sudo WebAuthn approvals."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from api.sudo_approvals import (
    ApprovalVerifier,
    SudoApprovalConfig,
    SudoApprovalConfigError,
    SudoApprovalConflict,
    SudoApprovalError,
    SudoApprovalExpired,
    SudoApprovalUnauthorized,
    _b64u,
    config_from_env,
    validate_browser_origin,
    validate_request_host,
)


ORIGIN = "https://approval.example.test"
RP_ID = "approval.example.test"
COMMAND = "/usr/bin/systemctl restart exact.service"
REQUESTER = "paseo:actor:trusted-123"
_CREDENTIAL_ID = b"deterministic-approval-credential"


class Clock:
    def __init__(self, value: int = 1_900_000_000):
        self.value = value

    def __call__(self) -> float:
        return float(self.value)

    def advance(self, seconds: int) -> None:
        self.value += seconds


class DeterministicBytes:
    def __init__(self):
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        block = hashlib.sha256(f"sudo-approval-test:{self.counter}".encode()).digest()
        return (block * ((length + len(block) - 1) // len(block)))[:length]


def _cbor_length(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")


def _cbor(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _cbor_length(0, value)
        return _cbor_length(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_length(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return _cbor_length(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _cbor_length(4, len(value)) + b"".join(_cbor(item) for item in value)
    if isinstance(value, dict):
        return _cbor_length(5, len(value)) + b"".join(
            _cbor(key) + _cbor(item) for key, item in value.items()
        )
    raise TypeError(type(value))


def _client_data(challenge: str, *, ceremony: str, origin: str = ORIGIN) -> bytes:
    return json.dumps(
        {
            "type": ceremony,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _private_key(seed: int = 7):
    return ec.derive_private_key(seed, ec.SECP256R1())


def _registration_payload(challenge: str, private_key, *, flags: int = 0x45):
    numbers = private_key.public_key().public_numbers()
    cose_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + (0).to_bytes(4, "big")
        + (b"\0" * 16)
        + len(_CREDENTIAL_ID).to_bytes(2, "big")
        + _CREDENTIAL_ID
        + _cbor(cose_key)
    )
    attestation = _cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
    raw_client = _client_data(challenge, ceremony="webauthn.create")
    return {
        "id": _b64u(_CREDENTIAL_ID),
        "rawId": _b64u(_CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(raw_client),
            "attestationObject": _b64u(attestation),
        },
    }


def _assertion_payload(
    challenge: str,
    private_key,
    *,
    credential_id: bytes = _CREDENTIAL_ID,
    flags: int = 0x05,
    sign_count: int = 1,
    origin: str = ORIGIN,
):
    auth_data = (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
    )
    raw_client = _client_data(challenge, ceremony="webauthn.get", origin=origin)
    signature = private_key.sign(
        auth_data + hashlib.sha256(raw_client).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "id": _b64u(credential_id),
        "rawId": _b64u(credential_id),
        "type": "public-key",
        "response": {
            "authenticatorData": _b64u(auth_data),
            "clientDataJSON": _b64u(raw_client),
            "signature": _b64u(signature),
            "userHandle": None,
        },
    }


@pytest.fixture
def verifier(tmp_path):
    clock = Clock()
    instance = ApprovalVerifier(
        SudoApprovalConfig(
            state_dir=tmp_path / "isolated-sudo-approval-state",
            rp_id=RP_ID,
            origin=ORIGIN,
            ttl_seconds=90,
        ),
        now=clock,
        random_bytes=DeterministicBytes(),
    )
    private_key = _private_key()
    enrollment = instance.start_enrollment("Deterministic test credential")
    options = instance.enrollment_options(enrollment["token"])
    instance.finish_enrollment(
        enrollment["token"],
        _registration_payload(options["challenge"], private_key),
    )
    return instance, clock, private_key


def _new_request(instance: ApprovalVerifier):
    return instance.create_request(command=COMMAND, requester=REQUESTER)


def _approve(instance: ApprovalVerifier, private_key, request, *, flags: int = 0x05):
    options = instance.approval_options(request["nonce"])
    payload = _assertion_payload(options["challenge"], private_key, flags=flags)
    return instance.approve(request["nonce"], payload), payload


def test_challenge_is_exact_canonical_request_binding(verifier):
    instance, _clock, _private_key = verifier
    request = _new_request(instance)
    binding = {
        "purpose": "hermes-sudo-approval-v1",
        "nonce": request["nonce"],
        "command_sha256": request["command_sha256"],
        "requester": request["requester"],
        "expires_at": request["expires_at"],
    }
    expected = _b64u(
        hashlib.sha256(
            json.dumps(
                binding,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).digest()
    )
    assert instance.approval_options(request["nonce"])["challenge"] == expected
    assert instance.approval_options(request["nonce"])["userVerification"] == "required"


def test_generic_signature_cannot_approve_exact_request(verifier):
    instance, _clock, private_key = verifier
    request = _new_request(instance)
    generic_challenge = _b64u(hashlib.sha256(b"generic login challenge").digest())
    generic_assertion = _assertion_payload(generic_challenge, private_key)

    with pytest.raises(SudoApprovalError, match="exact sudo request"):
        instance.approve(request["nonce"], generic_assertion)

    assert instance.request_status(request["nonce"])["state"] == "pending"


def test_consumer_rejects_changed_command_requester_and_expiry(verifier):
    instance, _clock, private_key = verifier
    request = _new_request(instance)
    _approve(instance, private_key, request)

    with pytest.raises(SudoApprovalUnauthorized, match="command"):
        instance.consume_approval(
            nonce=request["nonce"],
            command=COMMAND + " --changed",
            requester=REQUESTER,
            expires_at=request["expires_at"],
        )
    with pytest.raises(SudoApprovalUnauthorized, match="requester"):
        instance.consume_approval(
            nonce=request["nonce"],
            command=COMMAND,
            requester=REQUESTER + ":mutated",
            expires_at=request["expires_at"],
        )
    with pytest.raises(SudoApprovalUnauthorized, match="expiry"):
        instance.consume_approval(
            nonce=request["nonce"],
            command=COMMAND,
            requester=REQUESTER,
            expires_at=request["expires_at"] + 1,
        )

    consumed = instance.consume_approval(
        nonce=request["nonce"],
        command=COMMAND,
        requester=REQUESTER,
        expires_at=request["expires_at"],
    )
    assert consumed["state"] == "consumed"


def test_assertion_replay_and_consumption_replay_are_rejected(verifier):
    instance, _clock, private_key = verifier
    request = _new_request(instance)
    _approved, assertion = _approve(instance, private_key, request)

    with pytest.raises(SudoApprovalConflict, match="already decided"):
        instance.approve(request["nonce"], assertion)

    instance.consume_approval(
        nonce=request["nonce"],
        command=COMMAND,
        requester=REQUESTER,
        expires_at=request["expires_at"],
    )
    with pytest.raises(SudoApprovalConflict, match="not consumable"):
        instance.consume_approval(
            nonce=request["nonce"],
            command=COMMAND,
            requester=REQUESTER,
            expires_at=request["expires_at"],
        )


def test_expired_nonce_rejects_options_and_assertion(verifier):
    instance, clock, private_key = verifier
    request = _new_request(instance)
    challenge = instance.approval_options(request["nonce"])["challenge"]
    assertion = _assertion_payload(challenge, private_key)
    clock.advance(91)

    with pytest.raises(SudoApprovalExpired):
        instance.approval_options(request["nonce"])
    with pytest.raises(SudoApprovalExpired):
        instance.approve(request["nonce"], assertion)
    assert instance.request_status(request["nonce"])["state"] == "expired"


def test_approved_request_cannot_be_consumed_after_expiry(verifier):
    instance, clock, private_key = verifier
    request = _new_request(instance)
    _approve(instance, private_key, request)
    clock.advance(91)

    with pytest.raises(SudoApprovalExpired):
        instance.consume_approval(
            nonce=request["nonce"],
            command=COMMAND,
            requester=REQUESTER,
            expires_at=request["expires_at"],
        )
    assert instance.request_status(request["nonce"])["state"] == "expired"


def test_wrong_credential_is_rejected_without_authorizing(verifier):
    instance, _clock, wrong_private_key = verifier[0], verifier[1], _private_key(11)
    request = _new_request(instance)
    challenge = instance.approval_options(request["nonce"])["challenge"]
    assertion = _assertion_payload(
        challenge,
        wrong_private_key,
        credential_id=b"not-enrolled",
    )

    with pytest.raises(SudoApprovalUnauthorized, match="not authorized"):
        instance.approve(request["nonce"], assertion)
    assert instance.request_status(request["nonce"])["state"] == "pending"


def test_missing_uv_flag_is_rejected_even_with_valid_signature(verifier):
    instance, _clock, private_key = verifier
    request = _new_request(instance)
    challenge = instance.approval_options(request["nonce"])["challenge"]
    assertion = _assertion_payload(challenge, private_key, flags=0x01)

    with pytest.raises(SudoApprovalError, match="user verification"):
        instance.approve(request["nonce"], assertion)
    assert instance.request_status(request["nonce"])["state"] == "pending"


def test_duplicate_approve_and_deny_transitions_are_terminal(verifier):
    instance, _clock, private_key = verifier
    approved_request = _new_request(instance)
    _approved, assertion = _approve(instance, private_key, approved_request)

    with pytest.raises(SudoApprovalConflict):
        instance.deny(approved_request["nonce"])
    with pytest.raises(SudoApprovalConflict):
        instance.approve(approved_request["nonce"], assertion)

    denied_request = _new_request(instance)
    challenge = instance.approval_options(denied_request["nonce"])["challenge"]
    denied_assertion = _assertion_payload(challenge, private_key, sign_count=2)
    assert instance.deny(denied_request["nonce"])["state"] == "denied"
    with pytest.raises(SudoApprovalConflict):
        instance.deny(denied_request["nonce"])
    with pytest.raises(SudoApprovalConflict):
        instance.approve(denied_request["nonce"], denied_assertion)

    events = instance.audit_events()
    denied_events = [
        event
        for event in events
        if event.get("event") == "denied"
        and event.get("nonce") == denied_request["nonce"]
    ]
    assert len(denied_events) == 1
    assert all("command" not in event for event in events)


def test_unauthorized_enrollment_and_reuse_are_rejected(tmp_path):
    instance = ApprovalVerifier(
        SudoApprovalConfig(tmp_path / "state", RP_ID, ORIGIN, 90),
        now=Clock(),
        random_bytes=DeterministicBytes(),
    )
    with pytest.raises(SudoApprovalUnauthorized):
        instance.enrollment_options("untrusted-token")
    with pytest.raises(SudoApprovalUnauthorized):
        instance.enrollment_status("untrusted-token")

    enrollment = instance.start_enrollment("Trusted enrollment")
    options = instance.enrollment_options(enrollment["token"])
    instance.finish_enrollment(
        enrollment["token"],
        _registration_payload(options["challenge"], _private_key()),
    )
    with pytest.raises(SudoApprovalUnauthorized, match="already used"):
        instance.finish_enrollment(
            enrollment["token"],
            _registration_payload(options["challenge"], _private_key()),
        )


def test_enrollment_requires_uv_and_spends_failed_one_time_link(tmp_path):
    instance = ApprovalVerifier(
        SudoApprovalConfig(tmp_path / "state", RP_ID, ORIGIN, 90),
        now=Clock(),
        random_bytes=DeterministicBytes(),
    )
    enrollment = instance.start_enrollment("No UV")
    options = instance.enrollment_options(enrollment["token"])
    with pytest.raises(SudoApprovalError, match="user verification"):
        instance.finish_enrollment(
            enrollment["token"],
            _registration_payload(options["challenge"], _private_key(), flags=0x41),
        )
    with pytest.raises(SudoApprovalUnauthorized):
        instance.enrollment_options(enrollment["token"])


def test_state_is_private_and_separate(tmp_path, verifier):
    instance, _clock, _private_key = verifier
    _new_request(instance)
    assert instance.config.state_dir == tmp_path / "isolated-sudo-approval-state"
    assert instance.config.state_dir.stat().st_mode & 0o777 == 0o700
    assert instance.state_file.stat().st_mode & 0o777 == 0o600
    assert instance.lock_file.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("ttl", [59, 121])
def test_ttl_outside_approved_window_fails_closed(tmp_path, ttl):
    with pytest.raises(SudoApprovalConfigError, match="between 60 and 120"):
        ApprovalVerifier(SudoApprovalConfig(tmp_path / "state", RP_ID, ORIGIN, ttl))


def test_sessionless_ui_has_no_login_or_remote_admin_surface():
    root = Path(__file__).resolve().parent.parent
    html = (root / "static" / "sudo-approval.html").read_text(encoding="utf-8")
    js = (root / "static" / "sudo-approval.js").read_text(encoding="utf-8")
    routes = (root / "api" / "sudo_approval_routes.py").read_text(encoding="utf-8")
    docs = (root / "docs" / "sudo-approval.md").read_text(encoding="utf-8")

    assert "Exact command" in html
    assert "Requester" in html
    assert "Expires" in html
    assert "Approve with passkey" in html
    assert "Deny" in html
    assert "userVerification" not in html
    assert "credentials: 'omit'" in js
    assert "login" not in js.lower()
    assert "otp" not in js.lower()
    assert "/api/sudo-approval/create" not in routes
    assert "/api/sudo-approval/consume" not in routes
    assert "Cloudflare Access application" in docs


def test_no_live_or_broad_state_environment_is_used(verifier, monkeypatch):
    instance, _clock, _private_key = verifier
    monkeypatch.setenv("HERMES_WEBUI_STATE_DIR", "/definitely/not/the/verifier")
    request = _new_request(instance)
    assert request["state"] == "pending"
    assert "/definitely/not/the/verifier" not in str(instance.state_file)
    state = json.loads(instance.state_file.read_text(encoding="utf-8"))
    assert state["requests"][request["nonce"]]["purpose"] == "hermes-sudo-approval-v1"
    assert not (Path(os.environ["HERMES_WEBUI_STATE_DIR"]) / "state.json").exists()


class _RouteHandler:
    def __init__(self, headers):
        self.headers = headers


def test_narrow_route_requires_exact_host_and_browser_origin(verifier):
    instance, _clock, _private_key = verifier
    valid = _RouteHandler(
        {
            "Host": "approval.example.test",
            "Origin": ORIGIN,
            "Sec-Fetch-Site": "same-origin",
        }
    )
    validate_request_host(valid, instance)
    validate_browser_origin(valid, instance)

    with pytest.raises(SudoApprovalUnauthorized, match="configured origin"):
        validate_request_host(
            _RouteHandler({"Host": "webui.example.test"}),
            instance,
        )
    with pytest.raises(SudoApprovalUnauthorized, match="origin mismatch"):
        validate_browser_origin(
            _RouteHandler(
                {
                    "Host": "approval.example.test",
                    "Origin": "https://webui.example.test",
                    "Sec-Fetch-Site": "cross-site",
                }
            ),
            instance,
        )
    with pytest.raises(SudoApprovalUnauthorized, match="origin mismatch"):
        validate_browser_origin(
            _RouteHandler({"Host": "approval.example.test"}),
            instance,
        )


def test_only_narrow_sessionless_routes_bypass_webui_session(monkeypatch):
    import api.auth as auth

    assert auth._is_public_sudo_approval_path("/api/sudo-approval/options")
    assert auth._is_public_sudo_approval_path(
        "/api/sudo-approval/requests/abcdefghijklmnopqrstuvwxyz123456"
    )
    assert not auth._is_public_sudo_approval_path("/api/sudo-approval/create")
    assert not auth._is_public_sudo_approval_path("/api/sudo-approval/consume")

    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    handler = object()
    assert auth.check_auth(
        handler,
        urlparse("/sudo-approval/abcdefghijklmnopqrstuvwxyz123456"),
    )
    assert auth.check_auth(
        handler,
        urlparse("/sudo-enrollment/abcdefghijklmnopqrstuvwxyz123456"),
    )
    assert auth.check_auth(
        handler,
        urlparse("/api/sudo-approval/options"),
    )


def test_environment_config_rejects_broad_webui_state_child(monkeypatch):
    from api.config import STATE_DIR

    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_ENABLED", "1")
    monkeypatch.setenv(
        "HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR",
        str(STATE_DIR / "sudo-approval"),
    )
    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_RP_ID", RP_ID)
    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_ORIGIN", ORIGIN)
    with pytest.raises(SudoApprovalConfigError, match="broad WebUI state"):
        config_from_env()
