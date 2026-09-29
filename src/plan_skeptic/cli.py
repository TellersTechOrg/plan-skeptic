"""Command line entry point.

Exit codes: 0 nothing at or above --fail-on, 1 findings at or above it,
2 the input could not be reviewed. A failed read must never exit 0, because
"no findings" and "never looked" would then be the same signal.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .plan import PlanError, load_plan
from .report import render_json, render_sarif, render_text
from .rules import RULES, SEVERITY_ORDER, review


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plan-skeptic",
        description="Flag the parts of a Terraform/OpenTofu plan that need a human.",
        epilog="Produce input with: terraform show -json plan.out > plan.json (or tofu show -json).",
    )
    p.add_argument("plan", help="plan JSON file, or - for stdin")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--output", "-o", help="write the report here instead of stdout")
    p.add_argument(
        "--fail-on", choices=("high", "medium", "low", "never"), default="high",
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    p.add_argument(
        "--disable", action="append", default=[], metavar="RULE",
        help="skip a rule by id (repeatable), e.g. --disable PS002",
    )
    p.add_argument("--list-rules", action="store_true", help="print the rules and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if "--list-rules" in argv:
        for r in RULES.values():
            print(f"{r.id}  {r.severity:6}  {r.name}: {r.summary}")
        return 0
    args = build_parser().parse_args(argv)

    unknown = [d for d in args.disable if d.upper() not in RULES]
    if unknown:
        print(f"plan-skeptic: unknown rule id(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    try:
        if args.plan == "-":
            text = sys.stdin.read()
        else:
            with open(args.plan, encoding="utf-8") as fh:
                text = fh.read()
        changes = load_plan(text)
    except (OSError, UnicodeDecodeError, PlanError) as exc:
        print(f"plan-skeptic: {exc}", file=sys.stderr)
        return 2

    findings = review(changes, args.disable)
    if args.format == "sarif":
        out = render_sarif(findings, "plan.json" if args.plan == "-" else args.plan)
    elif args.format == "json":
        out = render_json(findings, len(changes))
    else:
        out = render_text(findings, len(changes))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        if args.format != "text":
            sys.stdout.write(render_text(findings, len(changes)))
    else:
        sys.stdout.write(out)

    if args.fail_on == "never":
        return 0
    floor = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= floor for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
