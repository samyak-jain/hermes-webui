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
import secrets
import tempfile
import threading
import time
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


_PURPOSE = "hermes-sudo-approval-v1"
_ENROLLMENT_PURPOSE = "hermes-sudo-approval-enrollment-v1"
_STATE_VERSION = 1
_DEFAULT_TTL_SECONDS = 90
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 120
_ENROLLMENT_TTL_SECONDS = 300
_MAX_COMMAND_BYTES = 64 * 1024
_MAX_REQUESTER_BYTES = 512
_MAX_RECORDS = 512
_TERMINAL_RETENTION_SECONDS = 24 * 60 * 60
_MAX_AUDIT_EVENTS = 2048
_THREAD_LOCK = threading.RLock()


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


@dataclass(frozen=True)
class SudoApprovalConfig:
    state_dir: Path
    rp_id: str
    origin: str
    ttl_seconds: int = _DEFAULT_TTL_SECONDS


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
    return SudoApprovalConfig(
        state_dir=state_dir,
        rp_id=rp_id,
        origin=str(config.origin).strip().rstrip("/"),
        ttl_seconds=int(config.ttl_seconds),
    )


def config_from_env() -> SudoApprovalConfig:
    """Load the fail-closed deployment contract for the approval verifier."""
    if not _truthy(os.getenv("HERMES_WEBUI_SUDO_APPROVAL_ENABLED")):
        raise SudoApprovalConfigError("sudo approval verifier is disabled")
    state_dir = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR", "").strip()
    rp_id = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_RP_ID", "").strip()
    origin = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_ORIGIN", "").strip()
    if not state_dir or not rp_id or not origin:
        raise SudoApprovalConfigError(
            "sudo approval requires an explicit state directory, RP ID, and origin"
        )
    ttl_raw = os.getenv("HERMES_WEBUI_SUDO_APPROVAL_TTL_SECONDS", "").strip()
    try:
        ttl = int(ttl_raw) if ttl_raw else _DEFAULT_TTL_SECONDS
    except ValueError as exc:
        raise SudoApprovalConfigError("sudo approval TTL must be an integer") from exc
    config = _validate_config(SudoApprovalConfig(Path(state_dir), rp_id, origin, ttl))
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


def _request_binding(
    *,
    nonce: str,
    command_sha256: str,
    requester: str,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "purpose": _PURPOSE,
        "nonce": nonce,
        "command_sha256": command_sha256,
        "requester": requester,
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
    ) -> None:
        self.config = _validate_config(config)
        self._now = now
        self._random_bytes = random_bytes
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
            row.update(
                {
                    "nonce": request.get("nonce"),
                    "command_sha256": request.get("command_sha256"),
                    "requester": request.get("requester"),
                    "expires_at": request.get("expires_at"),
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
        for nonce, request in list(requests.items()):
            if not isinstance(request, dict):
                requests.pop(nonce, None)
                continue
            expires_at = int(request.get("expires_at", 0))
            if request.get("state") in {"pending", "approved"} and expires_at <= now:
                request["state"] = "expired"
                request["decided_at"] = now
                self._audit(state, "expired", request=request)
            terminal_at = int(
                request.get("consumed_at")
                or request.get("decided_at")
                or expires_at
                or 0
            )
            if request.get("state") != "pending" and terminal_at + _TERMINAL_RETENTION_SECONDS <= now:
                requests.pop(nonce, None)
        if len(requests) > _MAX_RECORDS:
            ordered = sorted(
                requests,
                key=lambda key: int(requests[key].get("created_at", 0)),
            )
            for nonce in ordered[: len(requests) - _MAX_RECORDS]:
                if requests[nonce].get("state") != "pending":
                    requests.pop(nonce, None)

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

    def create_request(
        self,
        *,
        command: str,
        requester: str,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        command = self._validate_command(command)
        requester = self._validate_requester(requester)
        ttl = self.config.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if not (_MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS):
            raise SudoApprovalError("sudo approval TTL must be between 60 and 120 seconds")
        nonce = _b64u(self._random_bytes(32))
        now = int(self._now())
        expires_at = now + ttl
        command_sha256 = _command_hash(command)
        binding = _request_binding(
            nonce=nonce,
            command_sha256=command_sha256,
            requester=requester,
            expires_at=expires_at,
        )
        request = {
            **binding,
            "command": command,
            "challenge": _binding_challenge(binding),
            "created_at": now,
            "state": "pending",
        }
        with self._locked_state() as state:
            if not state["credentials"]:
                raise SudoApprovalConflict("no sudo approval credential is enrolled")
            state["requests"][nonce] = request
            self._audit(state, "request_created", request=request)
        return self._public_request(request)

    def _get_request(self, state: dict[str, Any], nonce: str) -> dict[str, Any]:
        request = state["requests"].get(str(nonce))
        if not isinstance(request, dict):
            raise SudoApprovalUnauthorized("approval request not found")
        if request.get("state") in {"pending", "approved"} and int(
            request.get("expires_at", 0)
        ) <= int(self._now()):
            request["state"] = "expired"
            request["decided_at"] = int(self._now())
            self._audit(state, "expired", request=request)
        return request

    @staticmethod
    def _public_request(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "nonce": request.get("nonce"),
            "command": request.get("command"),
            "command_sha256": request.get("command_sha256"),
            "requester": request.get("requester"),
            "created_at": request.get("created_at"),
            "expires_at": request.get("expires_at"),
            "state": request.get("state"),
        }

    def request_status(self, nonce: str) -> dict[str, Any]:
        with self._locked_state() as state:
            return self._public_request(self._get_request(state, nonce))

    def approval_options(self, nonce: str) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, nonce)
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

    def approve(self, nonce: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, nonce)
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
            if new_count and old_count and new_count <= old_count:
                self._audit(state, "approval_rejected", request=request, reason="sign_count")
                raise SudoApprovalUnauthorized("sudo approval sign counter did not advance")
            now = int(self._now())
            credential["sign_count"] = new_count or old_count
            credential["last_used_at"] = now
            request["state"] = "approved"
            request["decided_at"] = now
            request["credential_id"] = credential_id
            self._audit(state, "approved", request=request, credential_id=credential_id)
            return self._public_request(request)

    def deny(self, nonce: str) -> dict[str, Any]:
        with self._locked_state() as state:
            request = self._get_request(state, nonce)
            if request.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if request.get("state") != "pending":
                raise SudoApprovalConflict("approval request was already decided")
            request["state"] = "denied"
            request["decided_at"] = int(self._now())
            self._audit(state, "denied", request=request)
            return self._public_request(request)

    def consume_approval(
        self,
        *,
        nonce: str,
        command: str,
        requester: str,
        expires_at: int,
    ) -> dict[str, Any]:
        command = self._validate_command(command)
        requester = self._validate_requester(requester)
        with self._locked_state() as state:
            request = self._get_request(state, nonce)
            if request.get("state") == "expired":
                raise SudoApprovalExpired("approval request expired")
            if request.get("state") != "approved":
                raise SudoApprovalConflict("approval request is not consumable")
            mutation = None
            if (
                request.get("command") != command
                or not hmac.compare_digest(str(request.get("command_sha256")), _command_hash(command))
            ):
                mutation = "command"
            elif request.get("requester") != requester:
                mutation = "requester"
            elif int(request.get("expires_at", 0)) != int(expires_at):
                mutation = "expiry"
            if mutation:
                self._audit(state, "consume_rejected", request=request, reason=f"{mutation}_mutation")
                raise SudoApprovalUnauthorized(
                    f"approved request does not match the exact {mutation}"
                )
            request["state"] = "consumed"
            request["consumed_at"] = int(self._now())
            self._audit(
                state,
                "consumed",
                request=request,
                credential_id=request.get("credential_id"),
            )
            return self._public_request(request)

    def audit_events(self) -> list[dict[str, Any]]:
        with self._locked_state() as state:
            return [dict(row) for row in state["audit"] if isinstance(row, dict)]


def configured_verifier() -> ApprovalVerifier:
    """Construct the enabled verifier for request handlers."""
    return ApprovalVerifier.from_env()


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
