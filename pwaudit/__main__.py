"""Command line entry point."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import batch, crack_time, scoring

BAR_WIDTH = 20


def _bar(score: int) -> str:
    filled = int(BAR_WIDTH * (score / 4))
    return "[" + "#" * filled + "." * (BAR_WIDTH - filled) + "]"


def report_single(password: str, as_json: bool) -> int:
    result = scoring.evaluate(password)

    if as_json:
        payload = result.as_dict()
        payload["crack_time"] = crack_time.as_dict(result.entropy)
        print(json.dumps(payload, indent=2))
        return 0 if result.score >= 3 else 1

    print()
    print(f"  Strength   {_bar(result.score)}  {result.label} ({result.score}/4)")
    print(f"  Entropy    {result.entropy:.1f} bits"
          f"  (before penalties: {result.raw_entropy:.1f})")
    print(f"  Length     {result.password_length}"
          f"  |  character sets: {', '.join(result.pool_names) or 'none'}")

    print()
    print("  Estimated time to crack")
    for estimate in crack_time.estimate_all(result.entropy):
        print(f"    {estimate.description:<38} {estimate.human}")

    if result.findings:
        print()
        print("  Weaknesses found")
        for finding in result.findings:
            print(f"    - {finding.detail}")

    print()
    print("  Suggestions")
    for tip in result.suggestions:
        print(f"    - {tip}")
    print()

    return 0 if result.score >= 3 else 1


def report_batch(path: str, as_json: bool) -> int:
    try:
        rows = batch.audit_file(path)
    except FileNotFoundError:
        print(f"No such file: {path}", file=sys.stderr)
        return 2

    print(batch.to_json(rows) if as_json else batch.to_table(rows))
    return 0 if all(row.result.score >= 3 for row in rows) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwaudit",
        description="Audit password strength using entropy and pattern detection.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="password to check; omit to be prompted without echoing",
    )
    parser.add_argument("-f", "--file", help="audit a file of passwords, one per line")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.file:
        return report_batch(args.file, args.json)

    password = args.password
    if password is None:
        # Prompt rather than take it from argv, so it stays out of shell history.
        password = getpass.getpass("Password to audit (input hidden): ")
    if not password:
        print("No password given.", file=sys.stderr)
        return 2

    return report_single(password, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
