"""Audit a whole file of passwords at once.

Useful for checking an exported list from a password manager, or for looking at
a set of service accounts to see which ones need rotating first.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import crack_time, scoring


@dataclass
class BatchRow:
    identifier: str
    result: scoring.Result

    def as_dict(self) -> dict:
        data = self.result.as_dict()
        data["identifier"] = self.identifier
        data["crack_time"] = crack_time.as_dict(self.result.entropy)
        return data


def read_passwords(path: str) -> list[tuple[str, str]]:
    """Read a file of passwords, one per line.

    Blank lines and lines starting with # are skipped. A line may be either
    "password" or "label:password", so a report can name the account without
    the caller having to track line numbers.
    """
    entries = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ":" in line:
                label, password = line.split(":", 1)
                entries.append((label.strip() or f"line {number}", password))
            else:
                entries.append((f"line {number}", line))
    return entries


def audit_file(path: str) -> list[BatchRow]:
    return [BatchRow(label, scoring.evaluate(password)) for label, password in read_passwords(path)]


def summarise(rows: list[BatchRow]) -> dict:
    counts = {label: 0 for label in scoring.SCORE_LABELS.values()}
    for row in rows:
        counts[row.result.label] += 1
    weakest = min(rows, key=lambda r: r.result.entropy, default=None)
    return {
        "total": len(rows),
        "by_label": counts,
        "weakest": weakest.identifier if weakest else None,
    }


def to_json(rows: list[BatchRow], indent: int = 2) -> str:
    return json.dumps(
        {"summary": summarise(rows), "passwords": [row.as_dict() for row in rows]},
        indent=indent,
    )


def to_table(rows: list[BatchRow]) -> str:
    if not rows:
        return "No passwords found."

    width = max(len(row.identifier) for row in rows)
    width = max(width, len("identifier"))

    lines = [
        f"{'identifier'.ljust(width)}  {'score':<12} {'bits':>6}  offline fast hash",
        f"{'-' * width}  {'-' * 12} {'-' * 6}  {'-' * 22}",
    ]
    for row in rows:
        fast = next(
            e.human for e in crack_time.estimate_all(row.result.entropy)
            if e.key == "offline_fast_hash"
        )
        lines.append(
            f"{row.identifier.ljust(width)}  "
            f"{row.result.label:<12} {row.result.entropy:>6.1f}  {fast}"
        )

    counts = summarise(rows)["by_label"]
    tally = ", ".join(f"{n} {label}" for label, n in counts.items() if n)
    lines.append("")
    lines.append(f"{len(rows)} passwords: {tally}")
    return "\n".join(lines)
