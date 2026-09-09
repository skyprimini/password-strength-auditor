"""pwaudit: a password strength auditor built on entropy and pattern detection."""

__version__ = "0.1.0"

from .scoring import evaluate, Result  # noqa: F401
