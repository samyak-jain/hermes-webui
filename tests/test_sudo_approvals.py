"""Security contract tests for integrated request-bound sudo approvals."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    _canonical_json,
    _request_digest,
    config_from_env,
    validate_broker_authorization,
    validate_browser_origin,
    validate_request_host,
)


ORIGIN = "https://approval.example.test"
RP_ID = "approval.example.test"
BROKER_ID = "samyak-desktop"
BROKER_TOKEN = "test-broker-token-" + ("x" * 32)
REQUEST_ID = "11111111-1111-4111-8111-111111111111"
BROKER_NONCE = _b64u(hashlib.sha256(b"broker-nonce").digest())
COMMAND_ARGV = ["/usr/bin/systemctl", "restart", "exact service.service"]
COMMAND = "/usr/bin/systemctl restart 'exact service.service'"
REQUESTER = "paseo:worker-123"
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
        return _cbor_length(0 if value >= 0 else 1, value if value >= 0 else -1 - value)
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
    return {
        "id": _b64u(_CREDENTIAL_ID),
        "rawId": _b64u(_CREDENTIAL_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(
                _client_data(challenge, ceremony="webauthn.create")
            ),
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
    rp_id: str = RP_ID,
):
    auth_data = (
        hashlib.sha256(rp_id.encode()).digest()
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


def _transaction(clock: Clock, **changes):
    value = {
        "protocol_version": 1,
        "purpose": "sudo-approval/v1",
        "request_id": REQUEST_ID,
        "argv": list(COMMAND_ARGV),
        "command": COMMAND,
        "cwd": "/tmp",
        "requester_uid": 1000,
        "requester_worker_id": REQUESTER,
        "broker_id": BROKER_ID,
        "broker_nonce": BROKER_NONCE,
        "created_at": clock.value,
        "expires_at": clock.value + 90,
    }
    value.update(changes)
    return value


def _envelope(transaction, *, digest=None):
    return {
        "protocol_version": 1,
        "request": transaction,
        "request_digest": digest or _request_digest(transaction),
    }


def _url_capability(registration):
    parts = urlparse(registration["approval_url"]).path.split("/")
    return parts[-2], parts[-1]


@pytest.fixture
def verifier(tmp_path):
    clock = Clock()
    token_file = tmp_path / "broker.token"
    token_file.write_text(BROKER_TOKEN, encoding="ascii")
    token_file.chmod(0o600)
    config = SudoApprovalConfig(
        state_dir=tmp_path / "isolated-sudo-approval-state",
        rp_id=RP_ID,
        origin=ORIGIN,
        ttl_seconds=90,
        broker_id=BROKER_ID,
        broker_token_file=token_file,
    )
    instance = ApprovalVerifier(
        config,
        now=clock,
        random_bytes=DeterministicBytes(),
    )
    private_key = _private_key()
    enrollment = instance.start_enrollment("Deterministic credential")
    options = instance.enrollment_options(enrollment["token"])
    instance.finish_enrollment(
        enrollment["token"],
        _registration_payload(options["challenge"], private_key),
    )
    return instance, config, clock, private_key


def _register(instance, clock, **changes):
    transaction = _transaction(clock, **changes)
    registration = instance.register_request(_envelope(transaction))
    request_id, url_token = _url_capability(registration)
    return transaction, registration, request_id, url_token


def _approve(instance, private_key, request_id, url_token, *, flags=0x05, **kwargs):
    options = instance.approval_options(request_id, url_token)
    assertion = _assertion_payload(
        options["challenge"],
        private_key,
        flags=flags,
        **kwargs,
    )
    return instance.approve(request_id, url_token, assertion), assertion


def test_challenge_is_the_exact_canonical_transaction_digest(verifier):
    instance, _config, clock, _private_key = verifier
    transaction, registration, request_id, url_token = _register(instance, clock)
    digest = hashlib.sha256(_canonical_json(transaction)).hexdigest()
    expected_challenge = _b64u(bytes.fromhex(digest))

    options = instance.approval_options(request_id, url_token)
    assert registration["request_digest"] == digest
    assert options["challenge"] == expected_challenge
    assert options["userVerification"] == "required"


def test_shared_protocol_v1_golden_digest():
    assert (
        _request_digest(_transaction(Clock()))
        == "1770d92cb05b17e657533734c1cfd81b2a1800a9b890d3ed12ff72fd42420f23"
    )


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        ("command", {"argv": ["/usr/bin/false"], "command": "/usr/bin/false"}),
        ("cwd", {"cwd": "/"}),
        ("requester_uid", {"requester_uid": 1001}),
        ("requester_worker_id", {"requester_worker_id": "paseo:worker-other"}),
        ("broker_nonce", {"broker_nonce": "A" * 43}),
        (
            "request_id",
            {"request_id": "22222222-2222-4222-8222-222222222222"},
        ),
        ("expiry", {"expires_at": 1_900_000_091}),
    ],
)
def test_approval_a_cannot_consume_mutated_transaction_b(verifier, field, mutation):
    instance, _config, clock, private_key = verifier
    transaction, _registration, request_id, url_token = _register(instance, clock)
    approved, _assertion = _approve(instance, private_key, request_id, url_token)
    changed = copy.deepcopy(transaction)
    changed.update(mutation)

    with pytest.raises((SudoApprovalError, SudoApprovalUnauthorized)):
        instance.consume_approval(
            request_id=request_id,
            request=changed,
            request_digest=_request_digest(changed),
            decision_id=approved["decision_id"],
        )
    assert instance.decision_status(request_id)["status"] == "approved"


def test_approval_a_rejects_digest_and_decision_id_mutation(verifier):
    instance, _config, clock, private_key = verifier
    transaction, _registration, request_id, url_token = _register(instance, clock)
    approved, _assertion = _approve(instance, private_key, request_id, url_token)

    with pytest.raises(SudoApprovalUnauthorized, match="digest"):
        instance.consume_approval(
            request_id=request_id,
            request=transaction,
            request_digest="0" * 64,
            decision_id=approved["decision_id"],
        )
    with pytest.raises(SudoApprovalUnauthorized, match="decision_id"):
        instance.consume_approval(
            request_id=request_id,
            request=transaction,
            request_digest=_request_digest(transaction),
            decision_id="33333333-3333-4333-8333-333333333333",
        )


def test_replay_rejected_across_verifier_restarts(verifier):
    instance, config, clock, private_key = verifier
    transaction, _registration, request_id, url_token = _register(instance, clock)
    approved, assertion = _approve(instance, private_key, request_id, url_token)

    restarted = ApprovalVerifier(config, now=clock, random_bytes=DeterministicBytes())
    with pytest.raises(SudoApprovalConflict, match="already decided"):
        restarted.approve(request_id, url_token, assertion)
    consumed = restarted.consume_approval(
        request_id=request_id,
        request=transaction,
        request_digest=_request_digest(transaction),
        decision_id=approved["decision_id"],
    )
    assert consumed["status"] == "consumed"

    restarted_again = ApprovalVerifier(config, now=clock)
    assert restarted_again.decision_status(request_id)["status"] == "consumed"
    with pytest.raises(SudoApprovalConflict, match="not consumable"):
        restarted_again.consume_approval(
            request_id=request_id,
            request=transaction,
            request_digest=_request_digest(transaction),
            decision_id=approved["decision_id"],
        )


@pytest.mark.parametrize(
    ("accepted_count", "rollback_count"),
    [
        (5, 5),
        (5, 4),
        (1, 0),
    ],
)
def test_sign_counter_rollback_rejected_after_restart(
    verifier,
    accepted_count,
    rollback_count,
):
    instance, config, clock, private_key = verifier
    _transaction_value, _registration, request_id, url_token = _register(
        instance,
        clock,
    )
    _approve(
        instance,
        private_key,
        request_id,
        url_token,
        sign_count=accepted_count,
    )
    assert instance.list_credentials()[0]["sign_count"] == accepted_count

    restarted = ApprovalVerifier(config, now=clock)
    _transaction_value, _registration, second_id, second_token = _register(
        restarted,
        clock,
        request_id="22222222-2222-4222-8222-222222222222",
        broker_nonce="B" * 43,
    )
    options = restarted.approval_options(second_id, second_token)
    rollback = _assertion_payload(
        options["challenge"],
        private_key,
        sign_count=rollback_count,
    )
    with pytest.raises(SudoApprovalUnauthorized, match="counter"):
        restarted.approve(second_id, second_token, rollback)

    assert restarted.decision_status(second_id)["status"] == "pending"
    assert restarted.list_credentials()[0]["sign_count"] == accepted_count


def test_zero_sign_counter_is_accepted_and_persisted(verifier):
    instance, config, clock, private_key = verifier
    _transaction_value, _registration, request_id, url_token = _register(
        instance,
        clock,
    )
    _approve(instance, private_key, request_id, url_token, sign_count=0)

    restarted = ApprovalVerifier(config, now=clock)
    assert restarted.list_credentials()[0]["sign_count"] == 0


def test_bot_updates_delivery_uses_channel_scoped_exact_payload(verifier, tmp_path):
    instance, config, clock, _private_key = verifier
    transaction, registration, _request_id, _url_token = _register(instance, clock)
    received = {}

    class CaptureHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            received["path"] = self.path
            received["content_type"] = self.headers["Content-Type"]
            received["body"] = json.loads(self.rfile.read(length))
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        webhook_file = tmp_path / "bot-updates.webhook"
        webhook_file.write_text(
            f"http://127.0.0.1:{server.server_port}/discord-webhook",
            encoding="ascii",
        )
        webhook_file.chmod(0o600)
        notifier = ApprovalVerifier(
            SudoApprovalConfig(
                state_dir=config.state_dir,
                rp_id=config.rp_id,
                origin=config.origin,
                ttl_seconds=config.ttl_seconds,
                broker_id=config.broker_id,
                broker_token_file=config.broker_token_file,
                bot_updates_webhook_file=webhook_file,
            ),
            now=clock,
            allow_insecure_bot_updates_for_tests=True,
        )
        notifier.notify_bot_updates(
            {
                "protocol_version": 1,
                "channel": "bot-updates",
                "request_id": transaction["request_id"],
                "request_digest": registration["request_digest"],
                "command": transaction["command"],
                "requester_uid": transaction["requester_uid"],
                "requester_worker_id": transaction["requester_worker_id"],
                "approval_url": registration["approval_url"],
                "expires_at": transaction["expires_at"],
            }
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert received["path"] == "/discord-webhook"
    assert received["content_type"] == "application/json"
    assert received["body"]["allowed_mentions"] == {"parse": []}
    fields = {
        field["name"]: field["value"]
        for field in received["body"]["embeds"][0]["fields"]
    }
    assert fields == {
        "Exact command": transaction["command"],
        "Requester UID": str(transaction["requester_uid"]),
        "Requester worker": transaction["requester_worker_id"],
        "Expires at (Unix)": str(transaction["expires_at"]),
        "Review request": registration["approval_url"],
    }
    serialized = json.dumps(received["body"])
    assert BROKER_TOKEN not in serialized
    assert "approve" not in serialized.lower()
    assert "deny" not in serialized.lower()


def test_pending_and_approved_unconsumed_requests_expire_after_restart(verifier):
    instance, config, clock, private_key = verifier
    _pending_tx, _registration, pending_id, pending_token = _register(instance, clock)
    second_id = "22222222-2222-4222-8222-222222222222"
    approved_tx, _registration, approved_id, approved_token = _register(
        instance,
        clock,
        request_id=second_id,
        broker_nonce="B" * 43,
    )
    approved, _assertion = _approve(
        instance,
        private_key,
        approved_id,
        approved_token,
    )
    clock.advance(90)

    restarted = ApprovalVerifier(config, now=clock)
    assert restarted.decision_status(pending_id)["status"] == "expired"
    assert restarted.decision_status(approved_id)["status"] == "expired"
    with pytest.raises(SudoApprovalExpired):
        restarted.approval_options(pending_id, pending_token)
    with pytest.raises(SudoApprovalExpired):
        restarted.consume_approval(
            request_id=approved_id,
            request=approved_tx,
            request_digest=_request_digest(approved_tx),
            decision_id=approved["decision_id"],
        )


def test_missing_uv_wrong_credential_origin_and_rp_fail_closed(verifier):
    instance, _config, clock, private_key = verifier
    cases = [
        {"flags": 0x01},
        {"credential_id": b"not-enrolled"},
        {"origin": "https://wrong.example.test"},
        {"rp_id": "wrong.example.test"},
    ]
    for index, case in enumerate(cases, start=1):
        request_id = f"{index + 1:08d}-1111-4111-8111-111111111111"
        _transaction_value, _registration, rid, token = _register(
            instance,
            clock,
            request_id=request_id,
            broker_nonce=_b64u(hashlib.sha256(str(index).encode()).digest()),
        )
        options = instance.approval_options(rid, token)
        assertion = _assertion_payload(options["challenge"], private_key, **case)
        with pytest.raises(SudoApprovalError):
            instance.approve(rid, token, assertion)
        assert instance.decision_status(rid)["status"] == "pending"


def test_deny_is_terminal_and_url_token_has_no_approval_authority(verifier):
    instance, _config, clock, private_key = verifier
    _transaction_value, _registration, request_id, url_token = _register(instance, clock)
    wrong_token = "Z" * 43
    with pytest.raises(SudoApprovalUnauthorized, match="link"):
        instance.request_status(request_id, wrong_token)
    with pytest.raises(SudoApprovalUnauthorized, match="link"):
        instance.deny(request_id, wrong_token)

    assert instance.deny(request_id, url_token)["state"] == "denied"
    with pytest.raises(SudoApprovalConflict):
        instance.deny(request_id, url_token)
    options_challenge = _b64u(bytes.fromhex(_request_digest(_transaction(clock))))
    with pytest.raises(SudoApprovalConflict):
        instance.approve(
            request_id,
            url_token,
            _assertion_payload(options_challenge, private_key),
        )


def test_wrong_broker_identity_and_bearer_token_are_rejected(verifier):
    instance, _config, clock, _private_key = verifier
    wrong_identity = _transaction(clock, broker_id="other-desktop")
    with pytest.raises(SudoApprovalUnauthorized, match="broker identity"):
        instance.register_request(_envelope(wrong_identity))

    good = _HeaderHandler(
        {
            "Host": "approval.example.test",
            "Authorization": f"Bearer {BROKER_TOKEN}",
        }
    )
    validate_broker_authorization(good, instance)
    with pytest.raises(SudoApprovalUnauthorized, match="unauthorized"):
        validate_broker_authorization(
            _HeaderHandler(
                {
                    "Host": "approval.example.test",
                    "Authorization": "Bearer wrong-broker-token-value-xxxxxxxx",
                }
            ),
            instance,
        )


def test_state_is_private_durable_and_metadata_audit_omits_command(verifier):
    instance, config, clock, _private_key = verifier
    _register(instance, clock)
    assert config.state_dir.stat().st_mode & 0o777 == 0o700
    assert instance.state_file.stat().st_mode & 0o777 == 0o600
    assert instance.lock_file.stat().st_mode & 0o777 == 0o600
    assert COMMAND not in json.dumps(instance.audit_events())


def test_enrollment_requires_uv_and_is_single_use(tmp_path):
    clock = Clock()
    instance = ApprovalVerifier(
        SudoApprovalConfig(tmp_path / "state", RP_ID, ORIGIN, 90, BROKER_ID),
        now=clock,
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


@pytest.mark.parametrize("ttl", [59, 121])
def test_ttl_outside_protocol_window_fails_closed(tmp_path, ttl):
    with pytest.raises(SudoApprovalConfigError, match="between 60 and 120"):
        ApprovalVerifier(SudoApprovalConfig(tmp_path / "state", RP_ID, ORIGIN, ttl))


class _HeaderHandler:
    def __init__(self, headers):
        self.headers = headers


class _ResponseHandler(_HeaderHandler):
    def __init__(self, headers):
        super().__init__(headers)
        self.status = None
        self.response_headers = {}
        self.wfile = io.BytesIO()

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.response_headers[name] = value

    def end_headers(self):
        return None


def test_narrow_route_requires_exact_host_and_browser_origin(verifier):
    instance, _config, _clock, _private_key = verifier
    valid = _HeaderHandler(
        {
            "Host": "approval.example.test",
            "Origin": ORIGIN,
            "Sec-Fetch-Site": "same-origin",
        }
    )
    validate_request_host(valid, instance)
    validate_browser_origin(valid, instance)
    with pytest.raises(SudoApprovalUnauthorized):
        validate_request_host(_HeaderHandler({"Host": "webui.example.test"}), instance)
    with pytest.raises(SudoApprovalUnauthorized):
        validate_browser_origin(
            _HeaderHandler(
                {
                    "Host": "approval.example.test",
                    "Origin": "https://wrong.example.test",
                    "Sec-Fetch-Site": "cross-site",
                }
            ),
            instance,
        )


def test_sessionless_ui_and_broker_api_never_use_login_or_otp():
    root = Path(__file__).resolve().parent.parent
    html = (root / "static" / "sudo-approval.html").read_text(encoding="utf-8")
    js = (root / "static" / "sudo-approval.js").read_text(encoding="utf-8")
    routes = (root / "api" / "sudo_approval_routes.py").read_text(encoding="utf-8")
    assert "Exact command" in html
    assert "Working directory" in html
    assert "Approve with passkey" in html
    assert "credentials: 'omit'" in js
    assert "login" not in js.lower()
    assert "otp" not in js.lower()
    assert "validate_broker_authorization" in routes


def test_only_exact_sessionless_paths_bypass_webui_session(monkeypatch):
    import api.auth as auth

    assert auth._is_public_sudo_approval_path(
        f"/api/sudo-approval/requests/{REQUEST_ID}/{BROKER_NONCE}"
    )
    assert auth._is_public_sudo_approval_path(
        "/api/sudo-approval/broker/v1/requests"
    )
    assert not auth._is_public_sudo_approval_path(
        "/api/sudo-approval/broker/v1/admin"
    )
    assert not auth._is_public_sudo_approval_path("/api/sudo-approval/admin")
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: True)
    assert auth.check_auth(
        object(),
        urlparse(f"/sudo-approval/{REQUEST_ID}/{BROKER_NONCE}"),
    )


def test_no_access_approval_hostname_cannot_expose_broad_webui(monkeypatch):
    import api.auth as auth

    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_ORIGIN", ORIGIN)
    monkeypatch.setattr(auth, "is_auth_enabled", lambda: False)
    blocked = _ResponseHandler({"Host": "approval.example.test"})
    assert not auth.check_auth(blocked, urlparse("/api/sessions"))
    assert blocked.status == 404
    assert blocked.wfile.getvalue() == b'{"error":"Not found"}'

    approval = _ResponseHandler({"Host": "approval.example.test"})
    assert auth.check_auth(
        approval,
        urlparse(f"/sudo-approval/{REQUEST_ID}/{BROKER_NONCE}"),
    )
    static = _ResponseHandler({"Host": "approval.example.test"})
    assert auth.check_auth(static, urlparse("/static/sudo-approval.js"))

    ordinary_host = _ResponseHandler({"Host": "webui.example.test"})
    assert auth.check_auth(ordinary_host, urlparse("/api/sessions"))


def test_environment_config_requires_separate_state_and_broker_identity(
    monkeypatch,
    tmp_path,
):
    from api.config import STATE_DIR

    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_ENABLED", "1")
    monkeypatch.setenv(
        "HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR",
        str(STATE_DIR / "sudo-approval"),
    )
    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_RP_ID", RP_ID)
    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_ORIGIN", ORIGIN)
    monkeypatch.setenv("HERMES_WEBUI_SUDO_APPROVAL_BROKER_ID", BROKER_ID)
    monkeypatch.setenv(
        "HERMES_WEBUI_SUDO_APPROVAL_BROKER_TOKEN_FILE",
        str(tmp_path / "broker.token"),
    )
    monkeypatch.setenv(
        "HERMES_WEBUI_SUDO_APPROVAL_BOT_UPDATES_WEBHOOK_FILE",
        str(tmp_path / "bot-updates.webhook"),
    )
    with pytest.raises(SudoApprovalConfigError, match="broad WebUI state"):
        config_from_env()
