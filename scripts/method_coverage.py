#!/usr/bin/env python3
"""Report line coverage for a single function, not a whole file.

Standard coverage output is per file, which hides whether one particular
method is actually exercised. This finds the function in the AST, takes its
line range, and reports coverage for only those lines.

Usage:
    python3 -m coverage run -m unittest discover -s tests -t .
    python3 scripts/method_coverage.py pwaudit/scoring.py evaluate
"""

import ast
import sys

import coverage

THRESHOLD = 70.0


def method_lines(source_path: str, name: str) -> tuple[int, int]:
    tree = ast.parse(open(source_path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node.lineno, node.end_lineno
    raise SystemExit(f"No function named {name!r} in {source_path}")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit(__doc__)
    source_path, name = argv[1], argv[2]
    start, end = method_lines(source_path, name)

    cov = coverage.Coverage()
    cov.load()
    _, statements, _, missing, _ = cov.analysis2(source_path)

    in_method = [n for n in statements if start <= n <= end]
    missed = [n for n in missing if start <= n <= end]
    if not in_method:
        raise SystemExit(f"{name} has no measurable statements")

    covered = len(in_method) - len(missed)
    pct = 100.0 * covered / len(in_method)

    print(f"Method      : {name}()  in {source_path}")
    print(f"Lines       : {start}-{end}")
    print(f"Statements  : {len(in_method)}")
    print(f"Covered     : {covered}")
    print(f"Missing     : {missed or 'none'}")
    print(f"Coverage    : {pct:.1f}%  (threshold {THRESHOLD:.0f}%)")

    if pct <= THRESHOLD:
        print(f"FAIL: coverage of {name}() is not above {THRESHOLD:.0f}%")
        return 1
    print(f"PASS: coverage of {name}() is above {THRESHOLD:.0f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
