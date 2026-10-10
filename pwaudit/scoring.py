"""Turn a password into an entropy estimate and a 0-4 score.

The starting point is the size of the character pool the password draws from,
which gives a best-case entropy of length * log2(pool). Real passwords rarely
earn that, so the findings from patterns.py discount it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from . import patterns
from .patterns import Finding

CHARACTER_POOLS = (
    (re.compile(r"[a-z]"), 26, "lowercase"),
    (re.compile(r"[A-Z]"), 26, "uppercase"),
    (re.compile(r"[0-9]"), 10, "digits"),
    (re.compile(r"[ !-/:-@\[-`{-~]"), 33, "symbols"),
)

SCORE_LABELS = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "very strong",
}

# Entropy in bits at which each score begins.
SCORE_THRESHOLDS = ((60, 4), (45, 3), (32, 2), (20, 1))


@dataclass
class Result:
    password_length: int
    pool_size: int
    pool_names: list[str]
    raw_entropy: float
    entropy: float
    score: int
    label: str
    findings: list[Finding] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Plain dictionary, for JSON reports."""
        return {
            "length": self.password_length,
            "pool_size": self.pool_size,
            "character_sets": self.pool_names,
            "raw_entropy_bits": round(self.raw_entropy, 2),
            "entropy_bits": round(self.entropy, 2),
            "score": self.score,
            "label": self.label,
            "findings": [
                {"kind": f.kind, "detail": f.detail, "penalty": f.penalty}
                for f in self.findings
            ],
            "suggestions": self.suggestions,
        }


def character_pool(password: str) -> tuple[int, list[str]]:
    size = 0
    names = []
    for pattern, contribution, name in CHARACTER_POOLS:
        if pattern.search(password):
            size += contribution
            names.append(name)
    return size, names


def raw_entropy(password: str) -> float:
    pool, _ = character_pool(password)
    if pool == 0 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def _score_for(entropy: float) -> int:
    for threshold, score in SCORE_THRESHOLDS:
        if entropy >= threshold:
            return score
    return 0


def _suggestions(password: str, findings: list[Finding], pool_names: list[str]) -> list[str]:
    tips = []
    if len(password) < 12:
        tips.append("Use at least 12 characters; length helps more than complexity.")
    missing = {"lowercase", "uppercase", "digits", "symbols"} - set(pool_names)
    if missing:
        tips.append("Mix in " + ", ".join(sorted(missing)) + ".")

    kinds = {f.kind for f in findings}
    if kinds & {"common", "common-leet", "common-suffixed"}:
        tips.append("Avoid well-known passwords; substitutions like @ for a don't help.")
    if "sequence" in kinds:
        tips.append("Break up runs like 1234 or abcd.")
    if "repeat" in kinds or "repeat-block" in kinds:
        tips.append("Avoid repeating characters or repeating a short block.")
    if "keyboard" in kinds:
        tips.append("Avoid straight runs across the keyboard such as qwerty.")
    if "date" in kinds:
        tips.append("Leave out years and dates; they're easy to guess.")

    if not tips:
        tips.append("This password looks solid. Store it in a password manager.")
    return tips


def evaluate(password: str) -> Result:
    """Score a single password."""
    pool, names = character_pool(password)
    base = raw_entropy(password)
    findings = patterns.analyse(password)

    # Penalties compound rather than add, so three weak signals can't drive
    # entropy below zero and the worst single finding still dominates.
    remaining = 1.0
    for finding in findings:
        remaining *= finding.penalty

    entropy = base * remaining
    score = _score_for(entropy)

    return Result(
        password_length=len(password),
        pool_size=pool,
        pool_names=names,
        raw_entropy=base,
        entropy=entropy,
        score=score,
        label=SCORE_LABELS[score],
        findings=findings,
        suggestions=_suggestions(password, findings, names),
    )
