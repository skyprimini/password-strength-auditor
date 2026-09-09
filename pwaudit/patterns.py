"""Pattern detectors.

Each detector looks for one kind of predictable structure in a password and
reports how much it weakens the guess. A password that scores well on raw
entropy can still be terrible if it's a keyboard walk or a dictionary word
with digits stuck on the end, so these run before the final score is set.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Rows as they sit on a QWERTY keyboard, used to spot walks like "qwerty".
KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Characters people swap in to dodge a naive dictionary check.
LEET_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "@": "a",
    "$": "s", "!": "i", "|": "l",
}

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


@dataclass
class Finding:
    """One weakness found in a password."""

    kind: str
    detail: str
    # How much of the password's entropy this finding discounts, 0.0 to 1.0.
    penalty: float


def _load_common_passwords() -> set[str]:
    path = os.path.join(_DATA_DIR, "common_passwords.txt")
    try:
        with open(path, encoding="utf-8") as handle:
            return {line.strip().lower() for line in handle if line.strip()}
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = _load_common_passwords()


def normalise_leet(password: str) -> str:
    """Turn p@ssw0rd into password so substitutions don't hide a dictionary word."""
    return "".join(LEET_MAP.get(char, char) for char in password.lower())


def find_common_password(password: str) -> Finding | None:
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return Finding("common", "appears in a list of frequently used passwords", 0.95)

    normalised = normalise_leet(password)
    if normalised in COMMON_PASSWORDS:
        return Finding(
            "common-leet",
            f"is a common password with character substitutions ({normalised})",
            0.85,
        )

    # A common word with a short numeric or symbol suffix is still a common word.
    # Strip the suffix off the raw password first: normalising leet would turn
    # the trailing digits into letters and leave nothing to strip.
    stripped = re.sub(r"[0-9!@#$%^&*._-]+$", "", lowered)
    if len(stripped) >= 4:
        for candidate in (stripped, normalise_leet(stripped)):
            if candidate in COMMON_PASSWORDS:
                return Finding(
                    "common-suffixed",
                    f"is the common password '{candidate}' with characters appended",
                    0.75,
                )
    return None


def find_sequence(password: str, min_length: int = 4) -> Finding | None:
    """Catch runs like abcd, 1234, or their reverses."""
    lowered = password.lower()
    run = 1
    direction = 0

    for i in range(1, len(lowered)):
        delta = ord(lowered[i]) - ord(lowered[i - 1])
        if delta in (1, -1) and (direction == 0 or delta == direction):
            direction = delta
            run += 1
            if run >= min_length:
                return Finding(
                    "sequence",
                    f"contains a run of {run} sequential characters",
                    min(0.25 + 0.1 * run, 0.7),
                )
        else:
            run = 2 if delta in (1, -1) else 1
            direction = delta if delta in (1, -1) else 0
    return None


def find_repeat(password: str) -> Finding | None:
    """Catch aaaa and abcabcabc."""
    if re.search(r"(.)\1{2,}", password):
        return Finding("repeat", "repeats the same character three or more times", 0.5)

    for size in range(2, len(password) // 2 + 1):
        chunk = password[:size]
        if chunk * (len(password) // size) == password[: size * (len(password) // size)]:
            if len(password) // size >= 2 and len(password) % size == 0:
                return Finding("repeat-block", f"repeats the block '{chunk}'", 0.6)
    return None


def find_keyboard_walk(password: str, min_length: int = 4) -> Finding | None:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for start in range(len(row) - min_length + 1):
            for end in range(start + min_length, len(row) + 1):
                run = row[start:end]
                if run in lowered or run[::-1] in lowered:
                    return Finding(
                        "keyboard",
                        f"follows the keyboard row '{run}'",
                        min(0.3 + 0.08 * len(run), 0.65),
                    )
    return None


def find_date(password: str) -> Finding | None:
    """Years and dates are a small, heavily reused space."""
    for match in re.finditer(r"(19\d{2}|20[0-4]\d)", password):
        return Finding("date", f"contains what looks like a year ({match.group()})", 0.4)
    if re.search(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b", password):
        return Finding("date", "contains a date", 0.45)
    return None


DETECTORS = (
    find_common_password,
    find_sequence,
    find_repeat,
    find_keyboard_walk,
    find_date,
)


def analyse(password: str) -> list[Finding]:
    """Run every detector and return whatever it finds."""
    findings = []
    for detector in DETECTORS:
        found = detector(password)
        if found is not None:
            findings.append(found)
    return findings
