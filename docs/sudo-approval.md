# Request-bound sudo approval verifier

This optional subsystem is the gateway-side verifier for the desktop
`sudo-approval-broker`. It runs through the dedicated
`sudo_approval_server.py` entrypoint, not `server.py`. The ordinary WebUI has
no approval routes, public-path exemptions, state mount, broker token, or
notification credential.

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

The verifier entrypoint refuses startup unless every value is explicit, it is
running as a non-root dedicated UID, and all three mounted paths have that UID
as owner with exact private modes:

```sh
HERMES_WEBUI_SERVICE_MODE=verifier
HERMES_WEBUI_SUDO_APPROVAL_ENABLED=1
HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR=/var/lib/hermes-sudo-approval
HERMES_WEBUI_SUDO_APPROVAL_RP_ID=approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_ORIGIN=https://approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_TTL_SECONDS=90
HERMES_WEBUI_SUDO_APPROVAL_BROKER_ID=samyak-desktop
HERMES_WEBUI_SUDO_APPROVAL_BROKER_TOKEN_FILE=/run/secrets/sudo-approval-broker.token
HERMES_WEBUI_SUDO_APPROVAL_BOT_UPDATES_WEBHOOK_FILE=/run/secrets/sudo-approval-bot-updates.webhook
```

The private state directory must exist, be mode 0700, and must not be the broad
WebUI state directory or a child of it. State and lock files are mode 0600.
Both credential files must be regular mode-0600 files. Wrong ownership,
symlinks, missing mounts, malformed credentials, root execution, or unsafe
modes stop the verifier before it binds a socket. State writes use POSIX
locking and atomic fsync+rename persistence. Audit rows retain metadata and
digests but not command text or WebAuthn payloads.

The bot-updates file contains a channel-scoped Discord HTTPS webhook URL. It is
required when the verifier is enabled, must be mode 0600, and is never returned
to the desktop broker. The broker-authenticated `/v1/bot-updates` relay accepts
only the literal `bot-updates` target and fields matching an already-registered
request, then sends a notification with the exact command, requester UID and
worker ID, Unix expiry, and deep link. It exposes no approve or deny action.

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

- `POST /v1/bot-updates`
- `POST /api/sudo-approval/broker/v1/requests`
- `GET /api/sudo-approval/broker/v1/requests/<request-id>/decision`
- `POST /api/sudo-approval/broker/v1/requests/<request-id>/consume`

Enrollment:

- `/sudo-enrollment/<token>`
- `/api/sudo-approval/enrollments/<token>`
- `/api/sudo-approval/enrollment/options`, `/enrollment/finish`

## Kumo deployment boundary

Kumo routes `approval.<domain>` through the existing outbound Cloudflare
Tunnel to the verifier-only loopback port but creates no Access application
for that hostname. `webui.<domain>` routes to the separate broad WebUI
container and keeps its OTP policy.

Verifier state is mounted from a dedicated EFS directory outside
`/mnt/efs/hermes`; neither the gateway nor broad WebUI container can see it.
Kumo fetches the broker token and bot-updates webhook from dedicated SSM
parameters into tmpfs and mounts them read-only only into the verifier
container. The corresponding desktop token is installed separately as a
systemd credential.

UV proves the authenticator performed its configured user-verification method;
WebAuthn does not prove that method was specifically a fingerprint. A synced
platform passkey may exist on multiple devices, so a phone-only claim requires
separate authenticator enrollment/device policy.
