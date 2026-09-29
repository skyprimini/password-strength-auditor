"""Command line entry point."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import batch, breach, crack_time, report, scoring

BAR_WIDTH = 20


def _bar(score: int) -> str:
    filled = int(BAR_WIDTH * (score / 4))
    return "[" + "#" * filled + "." * (BAR_WIDTH - filled) + "]"


def report_single(password: str, as_json: bool, check_breaches: bool = False) -> int:
    result = scoring.evaluate(password)
    breach_result = breach.check(password) if check_breaches else None

    if as_json:
        payload = result.as_dict()
        payload["crack_time"] = crack_time.as_dict(result.entropy)
        if breach_result is not None:
            payload["breach"] = breach_result.as_dict()
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

    if breach_result is not None:
        print()
        print("  Breach check")
        print(f"    {breach_result.summary()}")
        if breach_result.breached:
            print("    Treat this password as compromised and change it everywhere.")

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

    if breach_result is not None and breach_result.breached:
        return 1
    return 0 if result.score >= 3 else 1


def report_batch(path: str, as_json: bool, html_path: str | None = None) -> int:
    try:
        rows = batch.audit_file(path)
    except FileNotFoundError:
        print(f"No such file: {path}", file=sys.stderr)
        return 2

    if html_path:
        report.write(rows, html_path)
        print(f"Wrote {html_path} ({len(rows)} passwords). No passwords are stored in it.")
    else:
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
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="write a standalone HTML report of a batch audit to FILE",
    )
    parser.add_argument(
        "--check-breaches",
        action="store_true",
        help="look the password up in the Have I Been Pwned corpus; only the first "
             "five characters of its SHA-1 hash leave this machine",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.html and not args.file:
        print("--html reports a batch audit, so it needs --file too.", file=sys.stderr)
        return 2

    if args.file:
        return report_batch(args.file, args.json, args.html)

    password = args.password
    if password is None:
        # Prompt rather than take it from argv, so it stays out of shell history.
        password = getpass.getpass("Password to audit (input hidden): ")
    if not password:
        print("No password given.", file=sys.stderr)
        return 2

    return report_single(password, args.json, args.check_breaches)


if __name__ == "__main__":
    raise SystemExit(main())
