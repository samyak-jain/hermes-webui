"""Request-bound, sessionless WebAuthn verification for sudo approvals.

This subsystem intentionally does not reuse WebUI login sessions, login
passkeys, or ``settings.json``.  Its state directory, RP ID, and origin are
explicit deployment inputs so a later deployment can place the approval page
on a narrow hostname without changing the broad WebUI authentication policy.

Only the browser ceremony is exposed through WebUI routes.  Creating approval
requests, consuming approvals, minting enrollment links, and revoking
credentials are trusted local operations provided by :class:`ApprovalVerifier`
and ``scripts/sudo_approval_admin.py``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

try:  # pragma: no cover - Windows is rejected when the feature is enabled.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except Exception:  # pragma: no cover - surfaced as a configuration error.
    InvalidSignature = Exception  # type: ignore[assignment]
    hashes = serialization = ec = None  # type: ignore[assignment]


_PURPOSE = "sudo-approval/v1"
_ENROLLMENT_PURPOSE = "hermes-sudo-approval-enrollment-v1"
_STATE_VERSION = 1
_DEFAULT_TTL_SECONDS = 90
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 120
_ENROLLMENT_TTL_SECONDS = 300
_MAX_COMMAND_BYTES = 64 * 1024
_MAX_REQUESTER_BYTES = 512
_MAX_ARGV_ITEMS = 256
_MAX_ARG_BYTES = 32 * 1024
_MAX_CWD_BYTES = 4096
_MAX_BROKER_ID_BYTES = 128
_MAX_RECORDS = 512
_TERMINAL_RETENTION_SECONDS = 24 * 60 * 60
_MAX_AUDIT_EVENTS = 2048
_THREAD_LOCK = threading.RLock()
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


class SudoApprovalError(ValueError):
    """Base class for expected verifier failures."""


class SudoApprovalConfigError(SudoApprovalError):
    """The verifier is disabled or has unsafe/incomplete configuration."""


class SudoApprovalUnauthorized(SudoApprovalError):
    """A trusted-path capability or credential was not accepted."""


class SudoApprovalExpired(SudoApprovalError):
    """A request or enrollment capability expired."""


class SudoApprovalConflict(SudoApprovalError):
    """A single-use state transition was already completed or is invalid."""


class SudoApprovalDeliveryError(SudoApprovalError):
    """The notification-only bot-updates delivery failed closed."""


@dataclass(frozen=True)
class SudoApprovalConfig:
    state_dir: Path
    rp_id: str
    origin: str
    ttl_seconds: int = _DEFAULT_TTL_SECONDS
    broker_id: str = "samyak-desktop"
    broker_token_file: Path | None = None
    bot_updates_webhook_file: Path | None = None


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(value: Any, *, field: str) -> bytes:
    if not isinstance(value, (str, bytes)):
        raise SudoApprovalError(f"Malformed {field}")
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SudoApprovalError(f"Malformed {field}") from exc
    value = value.strip()
    if not value:
        raise SudoApprovalError(f"Missing {field}")
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception as exc:
        raise SudoApprovalError(f"Malformed {field}") from exc


def _validate_config(config: SudoApprovalConfig) -> SudoApprovalConfig:
    rp_id = str(config.rp_id or "").strip().lower().rstrip(".")
    parsed = urlparse(str(config.origin or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
        raise SudoApprovalConfigError("sudo approval origin must be an exact http(s) origin")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise SudoApprovalConfigError("sudo approval origin must not contain credentials, path, query, or fragment")
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname != rp_id and not hostname.endswith(f".{rp_id}"):
        raise SudoApprovalConfigError("sudo approval RP ID must equal or suffix-match the origin hostname")
    if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SudoApprovalConfigError("sudo approval requires HTTPS except on loopback")
    if not (_MIN_TTL_SECONDS <= int(config.ttl_seconds) <= _MAX_TTL_SECONDS):
        raise SudoApprovalConfigError("sudo approval TTL must be between 60 and 120 seconds")
    state_dir = Path(config.state_dir).expanduser().resolve()
    broker_id = str(config.broker_id or "").strip()
    if (
        not broker_id
        or len(broker_id.encode("utf-8")) > _MAX_BROKER_ID_BYTES
        or not _IDENTITY_RE.fullmatch(broker_id)
    ):
        raise SudoApprovalConfigError("sudo approval broker identity is invalid")
    token_file = (
        Path(config.broker_token_file).expanduser().resolve()
        if config.broker_token_file is not None
        else None
    )
    webhook_file = (
        Path(config.bot_updates_webhook_file).expanduser().resolve()
        if config.bot_updates_webhook_file is not None
        else None
    )
    return SudoApprovalConfig(
        state_dir=state_dir,
        rp_id=rp_id,
        origin=str(config.origin).strip().rstrip("/"),
        ttl_seconds=int(config.ttl_seconds),
        broker_id=broker_id,
        broker_token_file=token_file,
        bot_updates_webhook_file=webhook_file,
    )


def config_from_env() -> SudoApprovalConfig:
    """Load the fail-closed deployment contract for the approval verifier."""
    if not _truthy(os.getenv("HERMES_WEBUI_SUDO_APPROVAL_ENABLED")):
        raise SudoApprovalConfigError("sudo approval verifier is disabled")
    state_dir = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR", "").strip()
    rp_id = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_RP_ID", "").strip()
    origin = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_ORIGIN", "").strip()
    broker_id = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_BROKER_ID", "").strip()
    broker_token_file = os.getenv(
        "HERMES_WEBUI_SUDO_APPROVAL_BROKER_TOKEN_FILE", ""
    ).strip()
    bot_updates_webhook_file = os.getenv(
        "HERMES_WEBUI_SUDO_APPROVAL_BOT_UPDATES_WEBHOOK_FILE", ""
    ).strip()
    if (
        not state_dir
        or not rp_id
        or not origin
        or not broker_id
        or not broker_token_file
        or not bot_updates_webhook_file
    ):
        raise SudoApprovalConfigError(
            "sudo approval requires state, RP/origin, broker identity, broker token, "
            "and bot-updates webhook files"
        )
    ttl_raw = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_TTL_SECONDS", "").strip()
    try:
        ttl = int(ttl_raw) if ttl_raw else _DEFAULT_TTL_SECONDS
    except ValueError as exc:
        raise SudoApprovalConfigError("sudo approval TTL must be an integer") from exc
    config = _validate_config(
        SudoApprovalConfig(
            Path(state_dir),
            rp_id,
            origin,
            ttl,
            broker_id,
            Path(broker_token_file),
            Path(bot_updates_webhook_file),
        )
    )
    from api.config import STATE_DIR

    broad_state_dir = STATE_DIR.resolve()
    if config.state_dir == broad_state_dir or broad_state_dir in config.state_dir.parents:
        raise SudoApprovalConfigError(
            "sudo approval state must not be the broad WebUI state directory or a child of it"
        )
    return config


@dataclass
class _Cbor:
    data: bytes
    pos: int = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.pos + length > len(self.data):
            raise SudoApprovalError("Malformed CBOR data")
        result = self.data[self.pos : self.pos + length]
        self.pos += length
        return result

    def item(self) -> Any:
        initial = self.read(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        value = self._value(additional)
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            return self.read(value)
        if major == 3:
            return self.read(value).decode("utf-8")
        if major == 4:
            return [self.item() for _ in range(value)]
        if major == 5:
            return {self.item(): self.item() for _ in range(value)}
        if major == 7 and value in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[value]
        raise SudoApprovalError("Unsupported CBOR data")

    def _value(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return self.read(1)[0]
        if additional == 25:
            return int.from_bytes(self.read(2), "big")
        if additional == 26:
            return int.from_bytes(self.read(4), "big")
        if additional == 27:
            return int.from_bytes(self.read(8), "big")
        raise SudoApprovalError("Indefinite CBOR values are not supported")


def _cbor_loads(data: bytes) -> Any:
    parser = _Cbor(data)
    value = parser.item()
    if parser.pos != len(data):
        raise SudoApprovalError("Trailing CBOR data")
    return value


def _public_key_from_cose(cose: Any):
    if ec is None:
        raise SudoApprovalConfigError("sudo approval requires the cryptography package")
    if not isinstance(cose, dict):
        raise SudoApprovalError("Malformed credential public key")
    if (
        cose.get(1) != 2
        or cose.get(3) != -7
        or cose.get(-1) != 1
        or not isinstance(cose.get(-2), bytes)
        or not isinstance(cose.get(-3), bytes)
    ):
        raise SudoApprovalError("Only ES256 P-256 credentials are supported")
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"),
            ec.SECP256R1(),
        )
        return numbers.public_key()
    except (TypeError, ValueError) as exc:
        raise SudoApprovalError("Malformed credential public key") from exc


def _parse_client_data(encoded: Any, *, expected_type: str) -> tuple[dict[str, Any], bytes]:
    raw = _b64u_decode(encoded, field="client data")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SudoApprovalError("Malformed client data") from exc
    if not isinstance(data, dict) or data.get("type") != expected_type:
        raise SudoApprovalError("Unexpected WebAuthn response type")
    if data.get("crossOrigin") not in {None, False}:
        raise SudoApprovalError("Cross-origin WebAuthn responses are not accepted")
    return data, raw


def _parse_authenticator_data(
    auth_data: bytes,
    *,
    rp_id: str,
    require_attested_credential: bool = False,
) -> dict[str, Any]:
    if len(auth_data) < 37:
        raise SudoApprovalError("Malformed authenticator data")
    expected_rp_hash = hashlib.sha256(rp_id.encode("idna")).digest()
    if not hmac.compare_digest(auth_data[:32], expected_rp_hash):
        raise SudoApprovalError("WebAuthn RP ID mismatch")
    flags = auth_data[32]
    if not (flags & 0x01):
        raise SudoApprovalError("WebAuthn user presence is required")
    if not (flags & 0x04):
        raise SudoApprovalError("WebAuthn user verification is required")
    if require_attested_credential and not (flags & 0x40):
        raise SudoApprovalError("Attested credential data is missing")
    return {
        "flags": flags,
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
        "rest": auth_data[37:],
    }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _request_digest(request: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(request)).hexdigest()


def _canonical_uuid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise SudoApprovalError(f"{field} is not a canonical UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise SudoApprovalError(f"{field} is not a canonical UUID") from exc
    return value


def _validate_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise SudoApprovalError("request_digest is not lowercase SHA-256")
    return value


def _validate_exact_transaction(
    value: Any,
    *,
    broker_id: str,
    now: int,
) -> dict[str, Any]:
    expected = {
        "protocol_version",
        "purpose",
        "request_id",
        "argv",
        "command",
        "cwd",
        "requester_uid",
        "requester_worker_id",
        "broker_id",
        "broker_nonce",
        "created_at",
        "expires_at",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise SudoApprovalError("transaction fields do not match protocol v1")
    if value["protocol_version"] != 1 or value["purpose"] != _PURPOSE:
        raise SudoApprovalError("transaction purpose or protocol is unsupported")
    request_id = _canonical_uuid(value["request_id"], field="request_id")
    argv_value = value["argv"]
    if (
        not isinstance(argv_value, list)
        or not argv_value
        or len(argv_value) > _MAX_ARGV_ITEMS
    ):
        raise SudoApprovalError("argv must be a non-empty bounded array")
    argv: list[str] = []
    total = 0
    for item in argv_value:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise SudoApprovalError("argv contains an invalid item")
        encoded = item.encode("utf-8")
        total += len(encoded)
        if len(encoded) > _MAX_ARG_BYTES or total > _MAX_ARG_BYTES:
            raise SudoApprovalError("argv is too large")
        argv.append(item)
    if not os.path.isabs(argv[0]):
        raise SudoApprovalError("argv[0] must be absolute")
    command = value["command"]
    if not isinstance(command, str) or command != shlex.join(argv):
        raise SudoApprovalError("command is not the canonical argv serialization")
    cwd = value["cwd"]
    if (
        not isinstance(cwd, str)
        or not os.path.isabs(cwd)
        or "\x00" in cwd
        or len(cwd.encode("utf-8")) > _MAX_CWD_BYTES
        or os.path.normpath(cwd) != cwd
    ):
        raise SudoApprovalError("cwd must be a normalized absolute path")
    requester_uid = value["requester_uid"]
    if (
        isinstance(requester_uid, bool)
        or not isinstance(requester_uid, int)
        or requester_uid < 0
    ):
        raise SudoApprovalError("requester_uid is invalid")
    requester_worker_id = value["requester_worker_id"]
    if (
        not isinstance(requester_worker_id, str)
        or len(requester_worker_id.encode("utf-8")) > _MAX_REQUESTER_BYTES
        or not _IDENTITY_RE.fullmatch(requester_worker_id)
    ):
        raise SudoApprovalError("requester_worker_id is invalid")
    if value["broker_id"] != broker_id:
        raise SudoApprovalUnauthorized("broker identity does not match this verifier")
    broker_nonce = value["broker_nonce"]
    if not isinstance(broker_nonce, str) or not _NONCE_RE.fullmatch(broker_nonce):
        raise SudoApprovalError("broker_nonce is not canonical base64url")
    created_at = value["created_at"]
    expires_at = value["expires_at"]
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at - created_at < _MIN_TTL_SECONDS
        or expires_at - created_at > _MAX_TTL_SECONDS
        or created_at > now + 30
        or expires_at <= now
    ):
        raise SudoApprovalExpired("transaction timestamps are invalid or expired")
    return {
        "protocol_version": 1,
        "purpose": _PURPOSE,
        "request_id": request_id,
        "argv": argv,
        "command": command,
        "cwd": cwd,
        "requester_uid": requester_uid,
        "requester_worker_id": requester_worker_id,
        "broker_id": broker_id,
        "broker_nonce": broker_nonce,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def _binding_challenge(binding: dict[str, Any]) -> str:
    return _b64u(hashlib.sha256(_canonical_json(binding)).digest())


def _empty_state() -> dict[str, Any]:
    return {
        "version": _STATE_VERSION,
        "credentials": [],
        "enrollments": {},
        "requests": {},
        "audit": [],
    }


class ApprovalVerifier:
    """Filesystem-backed request-bound WebAuthn verifier.

    All state transitions hold both an in-process lock and a POSIX file lock.
    The file lock makes the local admin CLI and threaded WebUI handler share one
    single-use state machine.
    """

    def __init__(
        self,
        config: SudoApprovalConfig,
        *,
        now: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        allow_insecure_bot_updates_for_tests: bool = False,
    ) -> None:
        self.config = _validate_config(config)
        self._now = now
        self._random_bytes = random_bytes
        self._allow_insecure_bot_updates_for_tests = (
            allow_insecure_bot_updates_for_tests
        )
        if fcntl is None:
            raise SudoApprovalConfigError("sudo approval requires POSIX file locking")
        if serialization is None or hashes is None or ec is None:
            raise SudoApprovalConfigError("sudo approval requires the cryptography package")

    @classmethod
    def from_env(cls) -> "ApprovalVerifier":
        return cls(config_from_env())

    @property
    def state_file(self) -> Path:
        return self.config.state_dir / "state.json"

    @property
    def lock_file(self) -> Path:
        return self.config.state_dir / ".lock"

    def _prepare_state_dir(self) -> None:
        self.config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.config.state_dir, 0o700)

    def _load_state(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return _empty_state()
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SudoApprovalConfigError("sudo approval state is unreadable") from exc
        if not isinstance(raw, dict) or raw.get("version") != _STATE_VERSION:
            raise SudoApprovalConfigError("sudo approval state has an unsupported format")
        state = _empty_state()
        for key in ("credentials", "enrollments", "requests", "audit"):
            if key in raw:
                state[key] = raw[key]
        if not isinstance(state["credentials"], list):
            raise SudoApprovalConfigError("sudo approval credential state is malformed")
        if not isinstance(state["enrollments"], dict) or not isinstance(state["requests"], dict):
            raise SudoApprovalConfigError("sudo approval transaction state is malformed")
        if not isinstance(state["audit"], list):
            state["audit"] = []
        return state

    def _save_state(self, state: dict[str, Any]) -> None:
        self._prepare_state_dir()
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=self.config.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.state_file)
            directory_fd = os.open(self.config.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @contextmanager
    def _locked_state(self) -> Iterator[dict[str, Any]]:
        self._prepare_state_dir()
        with _THREAD_LOCK:
            with self.lock_file.open("a+", encoding="utf-8") as lock_handle:
                os.chmod(self.lock_file, 0o600)
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                state = self._load_state()
                self._prune(state)
                try:
                    yield state
                finally:
                    self._save_state(state)
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _audit(
        self,
        state: dict[str, Any],
        event: str,
        *,
        request: dict[str, Any] | None = None,
        credential_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        row: dict[str, Any] = {"at": int(self._now()), "event": event}
        if request:
            transaction = request.get("transaction")
            if not isinstance(transaction, dict):
                transaction = request
            row.update(
                {
                    "request_id": transaction.get("request_id"),
                    "request_digest": request.get("request_digest"),
                    "requester_uid": transaction.get("requester_uid"),
                    "requester_worker_id": transaction.get("requester_worker_id"),
                    "expires_at": transaction.get("expires_at"),
                }
            )
        if credential_id:
            row["credential_id"] = credential_id
        if reason:
            row["reason"] = str(reason)[:160]
        audit = state.setdefault("audit", [])
        audit.append(row)
        del audit[:-_MAX_AUDIT_EVENTS]

    def _prune(self, state: dict[str, Any]) -> None:
        now = int(self._now())
        enrollments = state.get("enrollments", {})
        for digest, record in list(enrollments.items()):
            if not isinstance(record, dict) or int(record.get("expires_at", 0)) <= now:
                enrollments.pop(digest, None)
        requests = state.get("requests", {})
        for request_id, request in list(requests.items()):
            if not isinstance(request, dict):
                requests.pop(request_id, None)
                continue
            transaction = request.get("transaction")
            expires_at = (
                int(transaction.get("expires_at", 0))
                if isinstance(transaction, dict)
                else 0
            )
            if request.get("state") in {"pending", "approved"} and expires_at <= now:
                request["state"] = "expired"
                request["decided_at"] = expires_at
                self._audit(state, "expired", request=request)
            terminal_at = int(
                request.get("consumed_at")
                or request.get("decided_at")
                or expires_at
                or 0
            )
            if request.get("state") != "pending" and terminal_at + _TERMINAL_RETENTION_SECONDS <= now:
                requests.pop(request_id, None)
        if len(requests) > _MAX_RECORDS:
            ordered = sorted(
                requests,
                key=lambda key: int(
                    (requests[key].get("transaction") or {}).get("created_at", 0)
                ),
            )
            for request_id in ordered[: len(requests) - _MAX_RECORDS]:
                if requests[request_id].get("state") != "pending":
                    requests.pop(request_id, None)

    @staticmethod
    def _validate_command(command: Any) -> str:
        if not isinstance(command, str) or not command:
            raise SudoApprovalError("exact sudo command is required")
        if "\x00" in command:
            raise SudoApprovalError("sudo command must not contain NUL")
        if len(command.encode("utf-8")) > _MAX_COMMAND_BYTES:
            raise SudoApprovalError("sudo command is too large")
        return command

    @staticmethod
    def _validate_requester(requester: Any) -> str:
        if not isinstance(requester, str) or not requester.strip():
            raise SudoApprovalError("requester identity is required")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in requester):
            raise SudoApprovalError("requester identity contains control characters")
        requester = requester.strip()
        if len(requester.encode("utf-8")) > _MAX_REQUESTER_BYTES:
            raise SudoApprovalError("requester identity is too large")
        return requester

    def list_credentials(self) -> list[dict[str, Any]]:
        with self._locked_state() as state:
            return [
                {
                    "id": credential.get("id"),
                    "label": credential.get("label"),
                    "created_at": credential.get("created_at"),
                    "last_used_at": credential.get("last_used_at"),
                    "sign_count": credential.get("sign_count", 0),
                }
                for credential in state["credentials"]
                if isinstance(credential, dict)
            ]

    def start_enrollment(
        self,
        label: str,
        *,
        ttl_seconds: int = _ENROLLMENT_TTL_SECONDS,
    ) -> dict[str, Any]:
        label = str(label or "Approval passkey").strip()[:80] or "Approval passkey"
        if not (60 <= int(ttl_seconds) <= 900):
            raise SudoApprovalError("enrollment TTL must be between 60 and 900 seconds")
        token = _b64u(self._random_bytes(32))
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(self._now())
        with self._locked_state() as state:
            state["enrollments"][digest] = {
                "label": label,
                "created_at": now,
                "expires_at": now + int(ttl_seconds),
                "challenge": None,
            }
            self._audit(state, "enrollment_started")
        return {
            "token": token,
            "expires_at": now + int(ttl_seconds),
            "url": f"{self.config.origin}/sudo-enrollment/{token}",
        }

    def enrollment_status(self, token: str) -> dict[str, Any]:
        digest = hashlib.sha256(str(token).encode("ascii", "ignore")).hexdigest()
        with self._locked_state() as state:
            record = state["enrollments"].get(digest)
            if not isinstance(record, dict):
                raise SudoApprovalUnauthorized("enrollment link is invalid or expired")
            if int(record.get("expires_at", 0)) <= int(self._now()):
                state["enrollments"].pop(digest, None)
                raise SudoApprovalExpired("enrollment link expired")
            return {
                "label": record.get("label") or "Approval passkey",
                "expires_at": int(record["expires_at"]),
            }

    def enrollment_options(self, token: str) -> dict[str, Any]:
        digest = hashlib.sha256(str(token).encode("ascii", "ignore")).hexdigest()
        with self._locked_state() as state:
            record = state["enrollments"].get(digest)
            if not isinstance(record, dict):
                raise SudoApprovalUnauthorized("enrollment link is invalid or expired")
            if int(record.get("expires_at", 0)) <= int(self._now()):
                state["enrollments"].pop(digest, None)
                raise SudoApprovalExpired("enrollment link expired")
            challenge = record.get("challenge")
            if not isinstance(challenge, str):
                binding = {
                    "purpose": _ENROLLMENT_PURPOSE,
                    "token_sha256": digest,
                    "nonce": _b64u(self._random_bytes(32)),
                    "expires_at": int(record["expires_at"]),
                }
                challenge = _binding_challenge(binding)
                record["challenge"] = challenge
            existing = [
                {"type": "public-key", "id": credential["id"]}
                for credential in state["credentials"]
                if isinstance(credential, dict) and isinstance(credential.get("id"), str)
            ]
            return {
                "challenge": challenge,
                "rp": {"name": "Hermes sudo approval", "id": self.config.rp_id},
                "user": {
                    "id": _b64u(hashlib.sha256(f"{self.config.rp_id}:{_PURPOSE}".encode()).digest()[:32]),
                    "name": "sudo-approver",
                    "displayName": "Sudo approver",
                },
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "authenticatorSelection": {
                    "residentKey": "preferred",
                    "userVerification": "required",
                },
                "timeout": 60000,
                "attestation": "none",
                "excludeCredentials": existing,
            }

    def finish_enrollment(self, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        digest = hashlib.sha256(str(token).encode("ascii", "ignore")).hexdigest()
        with self._locked_state() as state:
            record = state["enrollments"].pop(digest, None)
            if not isinstance(record, dict):
                raise SudoApprovalUnauthorized("enrollment link is invalid or already used")
            if int(record.get("expires_at", 0)) <= int(self._now()):
                raise SudoApprovalExpired("enrollment link expired")
            expected_challenge = record.get("challenge")
            if not isinstance(expected_challenge, str):
                raise SudoApprovalConflict("enrollment options were not requested")
            response = payload.get("response")
            if not isinstance(response, dict):
                raise SudoApprovalError("Malformed enrollment response")
            client_data, _client_raw = _parse_client_data(
                response.get("clientDataJSON"),
                expected_type="webauthn.create",
            )
            if client_data.get("challenge") != expected_challenge:
                raise SudoApprovalError("Enrollment challenge mismatch")
            if client_data.get("origin") != self.config.origin:
                raise SudoApprovalError("Enrollment origin mismatch")
            attestation = _cbor_loads(
                _b64u_decode(response.get("attestationObject"), field="attestation object")
            )
            if (
                not isinstance(attestation, dict)
                or attestation.get("fmt") != "none"
                or attestation.get("attStmt") not in ({}, None)
                or not isinstance(attestation.get("authData"), bytes)
            ):
                raise SudoApprovalError("Only none-attestation enrollment is supported")
            parsed = _parse_authenticator_data(
                attestation["authData"],
                rp_id=self.config.rp_id,
                require_attested_credential=True,
            )
            rest = parsed["rest"]
            if len(rest) < 18:
                raise SudoApprovalError("Malformed attested credential data")
            credential_length = int.from_bytes(rest[16:18], "big")
            if credential_length <= 0 or len(rest) < 18 + credential_length:
                raise SudoApprovalError("Malformed credential ID")
            credential_id_bytes = rest[18 : 18 + credential_length]
            credential_id = _b64u(credential_id_bytes)
            submitted_id = payload.get("rawId") or payload.get("id")
            if not isinstance(submitted_id, str) or not hmac.compare_digest(submitted_id, credential_id):
                raise SudoApprovalError("Credential ID mismatch")
            if any(
                isinstance(existing, dict) and existing.get("id") == credential_id
                for existing in state["credentials"]
            ):
                raise SudoApprovalConflict("Credential is already enrolled")
            public_key = _public_key_from_cose(
                _cbor_loads(rest[18 + credential_length :])
            )
            public_key_pem = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            now = int(self._now())
            credential = {
                "id": credential_id,
                "label": str(record.get("label") or "Approval passkey")[:80],
                "public_key_pem": public_key_pem,
                "sign_count": parsed["sign_count"],
                "created_at": now,
                "last_used_at": None,
            }
            state["credentials"].append(credential)
            self._audit(state, "enrollment_completed", credential_id=credential_id)
            return {
                "ok": True,
                "credential": {"id": credential_id, "label": credential["label"]},
            }

    def revoke_credential(self, credential_id: str | None = None, *, revoke_all: bool = False) -> int:
        with self._locked_state() as state:
            credentials = state["credentials"]
            if revoke_all:
                removed = len(credentials)
                state["credentials"] = []
            else:
                if not credential_id:
                    raise SudoApprovalError("credential ID is required")
                state["credentials"] = [
                    credential
                    for credential in credentials
                    if not isinstance(credential, dict) or credential.get("id") != credential_id
                ]
                removed = len(credentials) - len(state["credentials"])
            if not removed:
                raise SudoApprovalError("credential not found")
            self._audit(
                state,
                "credential_revoked",
                credential_id=credential_id if not revoke_all else None,
                reason="all" if revoke_all else None,
            )
            return removed

    def register_request(self, envelope: Any) -> dict[str, Any]:
        if not isinstance(envelope, dict) or set(envelope) != {
            "protocol_version",
            "request",
            "request_digest",
        }:
            raise SudoApprovalError("broker registration envelope is malformed")
        if envelope["protocol_version"] != 1:
            raise SudoApprovalError("unsupported broker protocol version")
        now = int(self._now())
        transaction = _validate_exact_transaction(
            envelope["request"],
            broker_id=self.config.broker_id,
            now=now,
        )
        digest = _validate_digest(envelope["request_digest"])
        if not hmac.compare_digest(_request_digest(transaction), digest):
            raise SudoApprovalUnauthorized("request digest does not match transaction")
        request_id = transaction["request_id"]
        url_token = _b64u(self._random_bytes(32))
        request = {
            "transaction": transaction,
            "request_digest": digest,
            "url_token_sha256": hashlib.sha256(url_token.encode("ascii")).hexdigest(),
            "challenge": _b64u(bytes.fromhex(digest)),
            "state": "pending",
        }
        with self._locked_state() as state:
            if not state["credentials"]:
                raise SudoApprovalConflict("no sudo approval credential is enrolled")
            if request_id in state["requests"]:
                raise SudoApprovalConflict("request_id was already registered")
            if any(
                isinstance(existing, dict)
                and hmac.compare_digest(
                    str(existing.get("request_digest") or ""),
                    digest,
                )
                for existing in state["requests"].values()
            ):
                raise SudoApprovalConflict("request_digest was already registered")
            state["requests"][request_id] = request
            self._audit(state, "request_created", request=request)
        return {
            "protocol_version": 1,
            "request_id": request_id,
            "request_digest": digest,
            "broker_nonce": transaction["broker_nonce"],
            "expires_at": transaction["expires_at"],
            "approval_url": (
                f"{self.config.origin}/sudo-approval/{request_id}/{url_token}"
            ),
        }

    def _read_bot_updates_webhook(self) -> str:
        webhook_file = self.config.bot_updates_webhook_file
        if webhook_file is None:
            raise SudoApprovalConfigError(
                "sudo approval bot-updates webhook file is not configured"
            )
        try:
            stat = webhook_file.stat()
            if stat.st_mode & 0o077:
                raise SudoApprovalConfigError(
                    "sudo approval bot-updates webhook permissions are too broad"
                )
            webhook_url = webhook_file.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise SudoApprovalConfigError(
                "sudo approval bot-updates webhook is unavailable"
            ) from exc
        parsed = urlparse(webhook_url)
        path_parts = parsed.path.split("/")
        production_url = (
            parsed.scheme == "https"
            and parsed.hostname == "discord.com"
            and parsed.port is None
            and len(path_parts) == 5
            and path_parts[1:3] == ["api", "webhooks"]
            and bool(path_parts[3])
            and bool(path_parts[4])
        )
        test_url = (
            self._allow_insecure_bot_updates_for_tests
            and parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost"}
            and parsed.port is not None
            and bool(parsed.path)
        )
        if (
            not (production_url or test_url)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise SudoApprovalConfigError(
                "sudo approval bot-updates webhook must be a channel-scoped "
                "Discord HTTPS webhook"
            )
        return webhook_url

    @staticmethod
    def _bot_updates_message(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": "Sudo approval requested",
                    "fields": [
                        {
                            "name": "Exact command",
                            "value": payload["command"],
                            "inline": False,
                        },
                        {
                            "name": "Requester UID",
                            "value": str(payload["requester_uid"]),
                            "inline": True,
                        },
                        {
                            "name": "Requester worker",
                            "value": payload["requester_worker_id"],
                            "inline": True,
                        },
                        {
                            "name": "Expires at (Unix)",
                            "value": str(payload["expires_at"]),
                            "inline": False,
                        },
                        {
                            "name": "Review request",
                            "value": payload["approval_url"],
                            "inline": False,
                        },
                    ],
                    "footer": {
                        "text": (
                            f"request {payload['request_id']} · "
                            f"digest {payload['request_digest']}"
                        )
                    },
                }
            ],
        }

    def _deliver_bot_updates(self, webhook_url: str, payload: dict[str, Any]) -> None:
        body = _canonical_json(self._bot_updates_message(payload))
        request = urllib.request.Request(
            webhook_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "hermes-webui-sudo-approval/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status not in {200, 204}:
                    raise SudoApprovalDeliveryError(
                        "bot-updates webhook rejected notification"
                    )
                response.read(64 * 1024 + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SudoApprovalDeliveryError(
                "bot-updates webhook delivery failed"
            ) from exc

    def notify_bot_updates(self, payload: Any) -> None:
        expected = {
            "protocol_version",
            "channel",
            "request_id",
            "request_digest",
            "command",
            "requester_uid",
            "requester_worker_id",
            "approval_url",
            "expires_at",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise SudoApprovalError("bot-updates payload fields are invalid")
        if payload["protocol_version"] != 1 or payload["channel"] != "bot-updates":
            raise SudoApprovalError("bot-updates notification target is invalid")
        request_id = _canonical_uuid(payload["request_id"], field="request_id")
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            transaction = request["transaction"]
            expected_values = {
                "request_digest": request["request_digest"],
                "command": transaction["command"],
                "requester_uid": transaction["requester_uid"],
                "requester_worker_id": transaction["requester_worker_id"],
                "expires_at": transaction["expires_at"],
            }
            if any(payload[key] != value for key, value in expected_values.items()):
                raise SudoApprovalUnauthorized(
                    "bot-updates notification does not match the registered request"
                )
            parsed_url = urlparse(str(payload["approval_url"]))
            path_parts = parsed_url.path.split("/")
            if (
                parsed_url.scheme != "https"
                or parsed_url.netloc != urlparse(self.config.origin).netloc
                or len(path_parts) != 4
                or path_parts[1:3] != ["sudo-approval", request_id]
                or not _NONCE_RE.fullmatch(path_parts[3])
                or parsed_url.query
                or parsed_url.fragment
            ):
                raise SudoApprovalUnauthorized(
                    "bot-updates approval URL is not the registered request capability"
                )
            self._validate_url_token(request, path_parts[3])
        self._deliver_bot_updates(self._read_bot_updates_webhook(), payload)

    def _get_request(self, state: dict[str, Any], request_id: str) -> dict[str, Any]:
        request_id = _canonical_uuid(request_id, field="request_id")
        request = state["requests"].get(request_id)
        if not isinstance(request, dict):
            raise SudoApprovalUnauthorized("approval request not found")
        transaction = request.get("transaction")
        if not isinstance(transaction, dict):
            raise SudoApprovalConfigError("stored approval transaction is malformed")
        if (
            request.get("state") in {"pending", "approved"}
            and int(transaction.get("expires_at", 0)) <= int(self._now())
        ):
            request["state"] = "expired"
            request["decided_at"] = int(transaction["expires_at"])
            self._audit(state, "expired", request=request)
        return request

    @staticmethod
    def _public_request(request: dict[str, Any]) -> dict[str, Any]:
        transaction = dict(request["transaction"])
        result = {
            **transaction,
            "request_digest": request.get("request_digest"),
            "state": request.get("state"),
        }
        for field in ("decision_id", "decided_at", "consumed_at"):
            if field in request:
                result[field] = request[field]
        return result

    @staticmethod
    def _validate_url_token(request: dict[str, Any], url_token: str) -> None:
        if not isinstance(url_token, str) or not _NONCE_RE.fullmatch(url_token):
            raise SudoApprovalUnauthorized("approval link is invalid")
        supplied = hashlib.sha256(url_token.encode("ascii")).hexdigest()
        expected = str(request.get("url_token_sha256") or "")
        if not expected or not hmac.compare_digest(supplied, expected):
            raise SudoApprovalUnauthorized("approval link is invalid")

    def request_status(self, request_id: str, url_token: str) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            self._validate_url_token(request, url_token)
            return self._public_request(request)

    def decision_status(self, request_id: str) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            transaction = request["transaction"]
            status = str(request["state"])
            result: dict[str, Any] = {
                "protocol_version": 1,
                "request_id": transaction["request_id"],
                "request_digest": request["request_digest"],
                "broker_nonce": transaction["broker_nonce"],
                "expires_at": transaction["expires_at"],
                "status": status,
            }
            if status in {"approved", "denied", "consumed"}:
                result["decision_id"] = request["decision_id"]
                result["decided_at"] = request["decided_at"]
            elif status == "expired":
                result["decided_at"] = request["decided_at"]
            if status == "consumed":
                result["consumed_at"] = request["consumed_at"]
            return result

    def approval_options(
        self,
        request_id: str,
        url_token: str,
    ) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            self._validate_url_token(request, url_token)
            if request.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if request.get("state") != "pending":
                raise SudoApprovalConflict("approval request was already decided")
            credentials = [
                {"type": "public-key", "id": credential["id"]}
                for credential in state["credentials"]
                if isinstance(credential, dict) and isinstance(credential.get("id"), str)
            ]
            if not credentials:
                raise SudoApprovalConflict("no sudo approval credential is enrolled")
            return {
                "challenge": request["challenge"],
                "rpId": self.config.rp_id,
                "allowCredentials": credentials,
                "timeout": 60000,
                "userVerification": "required",
            }

    def approve(
        self,
        request_id: str,
        url_token: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            self._validate_url_token(request, url_token)
            if request.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if request.get("state") != "pending":
                raise SudoApprovalConflict("approval request was already decided")
            credential_id = payload.get("id")
            raw_credential_id = payload.get("rawId")
            if (
                not isinstance(credential_id, str)
                or not isinstance(raw_credential_id, str)
                or not hmac.compare_digest(credential_id, raw_credential_id)
            ):
                raise SudoApprovalUnauthorized("missing sudo approval credential")
            credential = next(
                (
                    item
                    for item in state["credentials"]
                    if isinstance(item, dict) and item.get("id") == credential_id
                ),
                None,
            )
            if credential is None:
                self._audit(state, "approval_rejected", request=request, reason="wrong_credential")
                raise SudoApprovalUnauthorized("credential is not authorized for sudo approval")
            response = payload.get("response")
            if not isinstance(response, dict):
                raise SudoApprovalError("Malformed approval response")
            client_data, client_raw = _parse_client_data(
                response.get("clientDataJSON"),
                expected_type="webauthn.get",
            )
            if client_data.get("challenge") != request.get("challenge"):
                self._audit(state, "approval_rejected", request=request, reason="challenge_mismatch")
                raise SudoApprovalError("Approval challenge does not match the exact sudo request")
            if client_data.get("origin") != self.config.origin:
                self._audit(state, "approval_rejected", request=request, reason="origin_mismatch")
                raise SudoApprovalError("Approval origin mismatch")
            auth_data = _b64u_decode(
                response.get("authenticatorData"),
                field="authenticator data",
            )
            try:
                parsed = _parse_authenticator_data(auth_data, rp_id=self.config.rp_id)
            except SudoApprovalError as exc:
                self._audit(state, "approval_rejected", request=request, reason=str(exc))
                raise
            signature = _b64u_decode(response.get("signature"), field="signature")
            try:
                public_key = serialization.load_pem_public_key(
                    str(credential.get("public_key_pem") or "").encode("ascii")
                )
                public_key.verify(
                    signature,
                    auth_data + hashlib.sha256(client_raw).digest(),
                    ec.ECDSA(hashes.SHA256()),
                )
            except (InvalidSignature, TypeError, ValueError) as exc:
                self._audit(state, "approval_rejected", request=request, reason="signature")
                raise SudoApprovalUnauthorized("sudo approval signature verification failed") from exc
            old_count = int(credential.get("sign_count") or 0)
            new_count = int(parsed["sign_count"])
            if (old_count != 0 or new_count != 0) and new_count <= old_count:
                self._audit(state, "approval_rejected", request=request, reason="sign_count")
                raise SudoApprovalUnauthorized("sudo approval sign counter did not advance")
            now = int(self._now())
            credential["sign_count"] = new_count
            credential["last_used_at"] = now
            request["state"] = "approved"
            request["decided_at"] = now
            request["decision_id"] = str(uuid.uuid4())
            request["credential_id"] = credential_id
            self._audit(state, "approved", request=request, credential_id=credential_id)
            return self._public_request(request)

    def deny(
        self,
        request_id: str,
        url_token: str,
    ) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, request_id)
            self._validate_url_token(request, url_token)
            if request.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if request.get("state") != "pending":
                raise SudoApprovalConflict("approval request was already decided")
            request["state"] = "denied"
            request["decided_at"] = int(self._now())
            request["decision_id"] = str(uuid.uuid4())
            self._audit(state, "denied", request=request)
            return self._public_request(request)

    def consume_approval(
        self,
        *,
        request_id: str,
        request: Any,
        request_digest: Any,
        decision_id: Any,
    ) -> dict[str, Any]:
        transaction = _validate_exact_transaction(
            request,
            broker_id=self.config.broker_id,
            now=int(self._now()),
        )
        digest = _validate_digest(request_digest)
        decision_id = _canonical_uuid(decision_id, field="decision_id")
        if transaction["request_id"] != request_id:
            raise SudoApprovalUnauthorized("consume request_id mismatch")
        if not hmac.compare_digest(_request_digest(transaction), digest):
            raise SudoApprovalUnauthorized("consume digest mismatch")
        with self._locked_state() as state:
            stored = self._get_request(state, request_id)
            if stored.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if stored.get("state") != "approved":
                raise SudoApprovalConflict("approval request is not consumable")
            if stored["transaction"] != transaction:
                self._audit(state, "consume_rejected", request=stored, reason="transaction_mutation")
                raise SudoApprovalUnauthorized("consume transaction mismatch")
            if not hmac.compare_digest(str(stored["request_digest"]), digest):
                raise SudoApprovalUnauthorized("consume digest mismatch")
            if stored.get("decision_id") != decision_id:
                raise SudoApprovalUnauthorized("consume decision_id mismatch")
            stored["state"] = "consumed"
            stored["consumed_at"] = int(self._now())
            self._audit(
                state,
                "consumed",
                request=stored,
                credential_id=stored.get("credential_id"),
            )
            return self.decision_status_from_record(stored)

    @staticmethod
    def decision_status_from_record(request: dict[str, Any]) -> dict[str, Any]:
        transaction = request["transaction"]
        return {
            "protocol_version": 1,
            "request_id": transaction["request_id"],
            "request_digest": request["request_digest"],
            "broker_nonce": transaction["broker_nonce"],
            "expires_at": transaction["expires_at"],
            "status": "consumed",
            "decision_id": request["decision_id"],
            "decided_at": request["decided_at"],
            "consumed_at": request["consumed_at"],
        }

    def audit_events(self) -> list[dict[str, Any]]:
        with self._locked_state() as state:
            return [dict(row) for row in state["audit"] if isinstance(row, dict)]


def configured_verifier() -> ApprovalVerifier:
    """Construct the enabled verifier for request handlers."""
    return ApprovalVerifier.from_env()


def validate_broker_authorization(handler, verifier: ApprovalVerifier) -> None:
    """Authenticate the one dedicated desktop broker without WebUI sessions."""
    token_file = verifier.config.broker_token_file
    if token_file is None:
        raise SudoApprovalConfigError("sudo approval broker token file is not configured")
    try:
        stat = token_file.stat()
        if stat.st_mode & 0o077:
            raise SudoApprovalConfigError("sudo approval broker token permissions are too broad")
        token = token_file.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise SudoApprovalConfigError("sudo approval broker token is unavailable") from exc
    if not (32 <= len(token) <= 512) or any(char.isspace() for char in token):
        raise SudoApprovalConfigError("sudo approval broker token is malformed")
    authorization = str(handler.headers.get("Authorization", ""))
    expected = f"Bearer {token}"
    if not hmac.compare_digest(authorization, expected):
        raise SudoApprovalUnauthorized("broker identity is unauthorized")


def validate_request_host(handler, verifier: ApprovalVerifier) -> None:
    """Require the configured narrow hostname on every approval HTTP route."""
    configured = urlparse(verifier.config.origin)
    expected = configured.netloc.lower()
    actual = str(handler.headers.get("Host", "")).strip().lower()
    if not actual or not hmac.compare_digest(actual, expected):
        raise SudoApprovalUnauthorized("sudo approval route is only available on its configured origin")


def validate_browser_origin(handler, verifier: ApprovalVerifier) -> None:
    """Require exact browser provenance for sessionless unsafe requests."""
    validate_request_host(handler, verifier)
    origin = str(handler.headers.get("Origin", "")).strip().rstrip("/")
    fetch_site = str(handler.headers.get("Sec-Fetch-Site", "")).strip().lower()
    if fetch_site == "cross-site" or not origin or not hmac.compare_digest(origin, verifier.config.origin):
        raise SudoApprovalUnauthorized("sudo approval request origin mismatch")
