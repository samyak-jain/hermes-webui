# Request-bound sudo approval verifier

This optional subsystem is the gateway-side verifier for the desktop
`sudo-approval-broker`. It is separate from WebUI login passkeys, sessions,
cookies, `settings.json`, and chat/tool approvals.

## One authoritative transaction

The desktop broker creates a closed protocol-v1 transaction containing:

- purpose `sudo-approval/v1`;
- canonical request UUID and 256-bit broker nonce;
- exact argv and its exact `shlex.join(argv)` display serialization;
- normalized absolute cwd;
- requester OS UID and worker ID;
- dedicated broker identity; and
- integer creation/expiry times with a 60–120 second lifetime.

Canonical JSON is UTF-8 with sorted keys and compact separators. Its SHA-256
is the `request_digest`; the WebAuthn challenge is the base64url form of those
same 32 digest bytes. The verifier independently validates the closed schema,
canonical command serialization, broker identity, timestamps, and digest
before storing the transaction unchanged.

The authenticator assertion must be `webauthn.get` for the exact origin/RP. The
verifier checks challenge, origin, RP-ID hash, UP, UV, credential authorization,
ES256 signature, and non-zero signature counter policy.

States are:

`pending → approved → consumed`

or:

`pending → denied|expired`

An approved-but-unconsumed request also becomes `expired` at its transaction
expiry. The authenticated broker must repeat the complete transaction, digest,
and decision ID to atomically receive a single `consumed` acknowledgment.
Only then may it contact its root executor. Duplicate approval, duplicate
consumption, mutation, mismatch, or restart replay fails closed.

## Authentication and URL authority

Create/status/consume routes require all of:

- the exact configured approval hostname;
- HTTPS in production;
- a bearer token loaded from a private file; and
- a transaction whose `broker_id` equals the configured dedicated identity.

The bearer token is shared only with the dedicated desktop broker service. It
is not accepted from a WebUI session and never appears in request state,
notification payloads, URLs, audits, or command environments.

The create response returns:

`/sudo-approval/<request-id>/<url-token>`

Only the URL token hash is stored. The token can display or deny that one
request. It cannot approve it, consume it, list requests, or access any other
WebUI surface. There is deliberately no WebUI login, Cloudflare Access OTP, or
request-list step before the passkey action. A leaked URL can cause denial of
service, never privilege.

## Configuration

The verifier is unavailable unless every value is explicit:

```sh
HERMES_WEBUI_SUDO_APPROVAL_ENABLED=1
HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR=/var/lib/hermes-sudo-approval
HERMES_WEBUI_SUDO_APPROVAL_RP_ID=approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_ORIGIN=https://approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_TTL_SECONDS=90
HERMES_WEBUI_SUDO_APPROVAL_BROKER_ID=samyak-desktop
HERMES_WEBUI_SUDO_APPROVAL_BROKER_TOKEN_FILE=/run/secrets/sudo-approval-broker.token
```

The private state directory must not be the broad WebUI state directory or a
child of it. It uses POSIX locking, atomic fsync+rename persistence, mode 0700
for the directory, and mode 0600 for files. Audit rows retain metadata and
digests but not command text or WebAuthn payloads.

## Credential administration

Credential enrollment/revocation remains local-only:

```sh
./scripts/sudo_approval_admin.py enroll --label "Phone approval passkey"
./scripts/sudo_approval_admin.py list-credentials
./scripts/sudo_approval_admin.py revoke --credential-id CREDENTIAL_ID
./scripts/sudo_approval_admin.py revoke --all
```

Enrollment URLs are high-entropy, five-minute, one-use capabilities. Enrollment
requires UP and UV and accepts only ES256 P-256 credentials with `none`
attestation. Revocation plus a new enrollment URL is the recovery path.

## Routes

Browser capability:

- `/sudo-approval/<request-id>/<url-token>`
- `/api/sudo-approval/requests/<request-id>/<url-token>`
- `/api/sudo-approval/options`, `/approve`, `/deny`

Broker bearer API:

- `POST /api/sudo-approval/broker/v1/requests`
- `GET /api/sudo-approval/broker/v1/requests/<request-id>/decision`
- `POST /api/sudo-approval/broker/v1/requests/<request-id>/consume`

Enrollment:

- `/sudo-enrollment/<token>`
- `/api/sudo-approval/enrollments/<token>`
- `/api/sudo-approval/enrollment/options`, `/enrollment/finish`

## Kumo deployment boundary

Kumo routes `approval.<domain>` through the existing outbound Cloudflare
Tunnel to the WebUI loopback port but creates no Access application for that
hostname. The existing `webui.<domain>` OTP policy stays unchanged.

Verifier state is mounted from a dedicated EFS directory outside
`/mnt/efs/hermes`; the broader gateway container cannot see it. Kumo fetches
the broker token from its own SSM parameter into tmpfs and mounts that file
read-only into WebUI. The corresponding desktop token is installed separately
as a systemd credential.

UV proves the authenticator performed its configured user-verification method;
WebAuthn does not prove that method was specifically a fingerprint. A synced
platform passkey may exist on multiple devices, so a phone-only claim requires
separate authenticator enrollment/device policy.
