#!/usr/bin/env python3
"""Trusted local administration for the sudo approval verifier.

This command deliberately has no remote API equivalent.  Filesystem access to
the verifier's private state directory is the enrollment/revocation/request
creation trust boundary until the separate trusted-agent/actor guard lands.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.sudo_approvals import ApprovalVerifier, SudoApprovalError  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Administer request-bound sudo approvals")
    subparsers = parser.add_subparsers(dest="action", required=True)

    enroll = subparsers.add_parser("enroll", help="mint a one-time trusted enrollment URL")
    enroll.add_argument("--label", default="Approval passkey")
    enroll.add_argument("--ttl", type=int, default=300)

    subparsers.add_parser("list-credentials", help="list approval credential metadata")

    revoke = subparsers.add_parser("revoke", help="revoke an approval credential")
    target = revoke.add_mutually_exclusive_group(required=True)
    target.add_argument("--credential-id")
    target.add_argument("--all", action="store_true")

    request = subparsers.add_parser("request", help="create an exact sudo approval request")
    request.add_argument("--requester", required=True)
    request.add_argument(
        "--command",
        required=True,
        help="exact command string; no shell normalization is performed",
    )
    request.add_argument("--ttl", type=int)

    status = subparsers.add_parser("status", help="show one request")
    status.add_argument("--nonce", required=True)

    consume = subparsers.add_parser("consume", help="consume one exact approved request")
    consume.add_argument("--nonce", required=True)
    consume.add_argument("--requester", required=True)
    consume.add_argument("--command", required=True)
    consume.add_argument("--expires-at", type=int, required=True)

    subparsers.add_parser("audit", help="show metadata-only approval audit events")
    return parser


def _run(args: argparse.Namespace) -> dict | list:
    verifier = ApprovalVerifier.from_env()
    if args.action == "enroll":
        return verifier.start_enrollment(args.label, ttl_seconds=args.ttl)
    if args.action == "list-credentials":
        return verifier.list_credentials()
    if args.action == "revoke":
        return {
            "revoked": verifier.revoke_credential(
                args.credential_id,
                revoke_all=args.all,
            )
        }
    if args.action == "request":
        result = verifier.create_request(
            command=args.command,
            requester=args.requester,
            ttl_seconds=args.ttl,
        )
        result["url"] = f"{verifier.config.origin}/sudo-approval/{result['nonce']}"
        return result
    if args.action == "status":
        return verifier.request_status(args.nonce)
    if args.action == "consume":
        return verifier.consume_approval(
            nonce=args.nonce,
            command=args.command,
            requester=args.requester,
            expires_at=args.expires_at,
        )
    if args.action == "audit":
        return verifier.audit_events()
    raise AssertionError(f"unsupported action: {args.action}")


def main() -> int:
    args = _parser().parse_args()
    try:
        result = _run(args)
    except SudoApprovalError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
