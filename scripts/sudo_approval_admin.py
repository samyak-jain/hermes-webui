#!/usr/bin/env python3
"""Trusted local credential administration for the sudo approval verifier."""
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
