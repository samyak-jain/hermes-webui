# Request-bound sudo approval verifier

This optional subsystem provides a sessionless WebAuthn ceremony for one exact
sudo request. It is intentionally separate from WebUI login passkeys, login
sessions, `settings.json`, and the chat/tool approval queue.

It is a local implementation checkpoint. It does **not** install sudoers rules,
execute sudo, expose a remote request-creation API, enroll a real credential, or
change Cloudflare/Kumo infrastructure.

## Security contract

An approval request contains:

- a 256-bit single-use nonce,
- the exact command string and its SHA-256 hash,
- the requester identity supplied by the trusted local caller,
- an integer expiry 60–120 seconds after creation, and
- a WebAuthn challenge equal to the SHA-256 digest of the canonical binding
  `{purpose, nonce, command_sha256, requester, expires_at}`.

The verifier accepts only `webauthn.get` assertions for its configured exact
origin and RP ID. It validates the RP ID hash, user-presence bit, user-
verification bit, ES256 signature, credential ID, and signature counter when
the authenticator supplies a non-zero counter. Approve changes `pending` to
`approved`; the trusted local consumer must then repeat the exact nonce,
command, requester, and expiry before the verifier atomically changes the
record to `consumed`. No second approval or consumption can succeed.

Deny is intentionally not a WebAuthn ceremony: knowledge of the unguessable
request URL can cancel a pending request but can never grant privilege. Denial
is a terminal single-use transition and is retained in the metadata-only audit
history. This trades possible denial-of-service by a leaked request URL for a
fast safe refusal path.

State uses an explicit private directory, POSIX file locking, atomic fsync +
rename writes, mode 0700 for the directory, and mode 0600 for files. Audit rows
contain command hashes, not command text. The active request record must retain
the exact command so it can be displayed and matched at consumption.

## Fail-closed configuration

The verifier is unavailable unless all of these are explicitly configured:

```sh
HERMES_WEBUI_SUDO_APPROVAL_ENABLED=1
HERMES_WEBUI_SUDO_APPROVAL_STATE_DIR=/var/lib/hermes-sudo-approval
HERMES_WEBUI_SUDO_APPROVAL_RP_ID=approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_ORIGIN=https://approval.example.com
HERMES_WEBUI_SUDO_APPROVAL_TTL_SECONDS=90
```

The origin must be exact and HTTPS except for loopback development. Every
approval HTTP route also requires the request `Host` to match that configured
origin. Unsafe browser calls require the exact configured `Origin`; WebUI
cookies and CSRF tokens are neither read nor accepted as approval authority.

## Trusted local administration

The administration command has no remote route:

```sh
./scripts/sudo_approval_admin.py enroll --label "Phone approval passkey"
./scripts/sudo_approval_admin.py list-credentials
./scripts/sudo_approval_admin.py revoke --credential-id CREDENTIAL_ID
./scripts/sudo_approval_admin.py revoke --all
```

`enroll` prints a high-entropy, five-minute, one-time URL. Registration requires
UP and UV and accepts only an ES256 P-256 credential with `none` attestation.
The token is stored only as a SHA-256 digest. Revocation followed by a newly
minted enrollment URL is the re-enrollment/recovery path.

The local request/consumer seam is:

```sh
./scripts/sudo_approval_admin.py request \
  --requester 'paseo:actor-id' \
  --command '/usr/bin/systemctl restart example.service'

./scripts/sudo_approval_admin.py consume \
  --nonce NONCE \
  --requester 'paseo:actor-id' \
  --command '/usr/bin/systemctl restart example.service' \
  --expires-at UNIX_SECONDS
```

The command is an exact UTF-8 string. No shell parsing, whitespace
normalization, argument reordering, or path resolution occurs. A future sudo
broker must define and preserve the exact representation it executes; it must
not reconstruct a different shell command after consumption.

## Sessionless browser routes

- `/sudo-approval/<nonce>` — exact request, requester, expiry, Approve/Deny.
- `/sudo-enrollment/<token>` — trusted-path one-time registration.
- `/api/sudo-approval/requests/<nonce>` — one request only.
- `/api/sudo-approval/options`, `/approve`, `/deny` — browser ceremony.
- `/api/sudo-approval/enrollments/<token>`, `/enrollment/options`,
  `/enrollment/finish` — one-time enrollment ceremony.

There is no login, OTP, broad WebUI session, request-list endpoint, remote
request-creation endpoint, or remote consume endpoint.

## Prepared Kumo/Cloudflare shape (not applied)

Later Kumo review should add a dedicated hostname such as
`approval.<domain>` to the existing Cloudflare Tunnel and route it to the same
loopback WebUI origin. Configure the explicit verifier environment values
and mount a dedicated state path into the WebUI container. Do not put approval
state under `/opt/data/webui` and do not reuse `/opt/data/webui/passkeys.json`.

The existing `webui.<domain>` Cloudflare Access application and operator-email
OTP policy should remain unchanged. The dedicated approval hostname must not
redirect through that login/OTP flow: the page's only positive authority is
the per-request UV-required WebAuthn assertion. The request path is already
host-pinned in the application, so serving it through the broad WebUI hostname
fails closed.

Before any remote request/consume surface is added, the parent trusted-
agent/actor guard must define and enforce:

- which local actor may create a request,
- the stable requester identity that is bound into it,
- how that actor authenticates to a verifier hosted on Kumo,
- how the returned single-use approval reaches a narrowly privileged desktop
  sudo broker, and
- the exact argv/string serialization used by that broker.

No Cloudflare resource, tunnel ingress, container mount, environment setting,
sudoers entry, host service, or credential enrollment is part of this
checkpoint.

## Authenticator scope

UV proves that the authenticator performed its configured user-verification
method. WebAuthn does not prove that the method was specifically a fingerprint,
and a synchronized platform passkey may exist on more than one device. If the
deployment claim requires a phone-only/device-bound key, enrollment policy and
attestation/device management need a separately reviewed enforcement mechanism.
