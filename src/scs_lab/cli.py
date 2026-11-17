"""Command line entry points: render policies and check one request."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy_eval import Request, Unsupported, evaluate
from .render import TEMPLATE_VARS, render_all, render_policy


def _parse_context(items: list[str]) -> dict[str, str]:
    context = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"--context expects key=value, got {item!r}")
        context[key] = value
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scs-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    render = sub.add_parser("render", help="write rendered example policies as JSON")
    render.add_argument("--out", default="build/policies")

    check = sub.add_parser("check", help="evaluate one request against one rendered policy")
    check.add_argument("--policy", required=True, choices=sorted(TEMPLATE_VARS))
    check.add_argument("--action", required=True)
    check.add_argument("--resource", default="*")
    check.add_argument("--principal-arn")
    check.add_argument("--principal-service")
    check.add_argument("--context", action="append", default=[], metavar="KEY=VALUE")

    args = parser.parse_args(argv)
    if args.command == "render":
        for path in render_all(Path(args.out)):
            print(path)
        return 0

    request = Request(
        action=args.action,
        resource=args.resource,
        context=_parse_context(args.context),
        principal_arn=args.principal_arn,
        principal_service=args.principal_service,
    )
    try:
        decision = evaluate(render_policy(args.policy), request)
    except Unsupported as err:
        print(json.dumps({"error": f"unsupported: {err}"}))
        return 2
    print(
        json.dumps(
            {
                "policy": args.policy,
                "decision": decision.decision,
                "matched_allow": decision.matched_allow,
                "matched_deny": decision.matched_deny,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
