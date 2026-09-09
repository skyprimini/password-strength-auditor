"""Translate entropy into how long an attacker would need.

Bits of entropy on their own don't mean much to most people. The same password
that would hold for centuries against a login form falls in minutes to someone
who has stolen the hash and is running GPUs against it, so we report several
scenarios rather than one number.
"""

from __future__ import annotations

from dataclasses import dataclass

# Guesses per second each kind of attacker can manage.
SCENARIOS = (
    ("online_throttled", "Online attack, rate limited", 10),
    ("online_unthrottled", "Online attack, no rate limit", 1_000),
    ("offline_slow_hash", "Offline attack, slow hash (bcrypt)", 10_000),
    ("offline_fast_hash", "Offline attack, fast hash (SHA-1)", 10_000_000_000),
)

SECOND = 1.0
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
DAY = 24 * HOUR
MONTH = 30 * DAY
YEAR = 365 * DAY
CENTURY = 100 * YEAR


@dataclass
class Estimate:
    key: str
    description: str
    guesses_per_second: float
    seconds: float
    human: str


def guesses_for(entropy_bits: float) -> float:
    """Expected guesses to find the password, which is half the keyspace."""
    if entropy_bits <= 0:
        return 1.0
    # 2 ** entropy can overflow a float for very long passwords, so cap it at a
    # value already far beyond any meaningful timescale.
    if entropy_bits > 256:
        entropy_bits = 256
    return (2.0 ** entropy_bits) / 2.0


def humanise(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    if seconds < MINUTE:
        return f"{seconds:.0f} seconds"
    if seconds < HOUR:
        return f"{seconds / MINUTE:.0f} minutes"
    if seconds < DAY:
        return f"{seconds / HOUR:.0f} hours"
    if seconds < MONTH:
        return f"{seconds / DAY:.0f} days"
    if seconds < YEAR:
        return f"{seconds / MONTH:.0f} months"
    if seconds < CENTURY:
        return f"{seconds / YEAR:.0f} years"
    if seconds < CENTURY * 1_000:
        return f"{seconds / CENTURY:.0f} centuries"
    return "longer than recorded history"


def estimate_all(entropy_bits: float) -> list[Estimate]:
    guesses = guesses_for(entropy_bits)
    estimates = []
    for key, description, rate in SCENARIOS:
        seconds = guesses / rate
        estimates.append(
            Estimate(
                key=key,
                description=description,
                guesses_per_second=rate,
                seconds=seconds,
                human=humanise(seconds),
            )
        )
    return estimates


def as_dict(entropy_bits: float) -> dict:
    return {e.key: {"description": e.description, "time": e.human} for e in estimate_all(entropy_bits)}
