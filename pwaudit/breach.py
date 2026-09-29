"""Check a password against the Have I Been Pwned corpus.

The obvious way to ask "has this password been breached" is to send it to a
server, which is exactly what you should never do. The range API avoids that
with k-anonymity: hash the password with SHA-1, send only the first five
characters of the hash, and get back every suffix sharing that prefix. The
match happens locally, so the server never learns which password was asked
about, and never sees the password itself.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass

API_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT = 6.0
PREFIX_LENGTH = 5


class BreachLookupError(Exception):
    """Raised when the corpus could not be reached."""


@dataclass
class BreachResult:
    checked: bool
    count: int = 0
    error: str | None = None

    @property
    def breached(self) -> bool:
        return self.count > 0

    def summary(self) -> str:
        if not self.checked:
            return f"not checked ({self.error})"
        if self.count == 0:
            return "not found in the breach corpus"
        if self.count == 1:
            return "found once in the breach corpus"
        return f"found {self.count:,} times in the breach corpus"

    def as_dict(self) -> dict:
        return {
            "checked": self.checked,
            "breached": self.breached,
            "count": self.count,
            "error": self.error,
        }


def split_hash(password: str) -> tuple[str, str]:
    """Return the hash prefix that gets sent and the suffix kept local."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def fetch_range(prefix: str, opener=urllib.request.urlopen) -> str:
    """Fetch every hash suffix sharing this prefix."""
    request = urllib.request.Request(
        API_URL + prefix,
        headers={"User-Agent": "pwaudit (https://github.com/skyprimini/password-strength-auditor)"},
    )
    try:
        with opener(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise BreachLookupError(f"could not reach the breach corpus: {exc.reason}") from exc
    except OSError as exc:
        raise BreachLookupError(f"could not reach the breach corpus: {exc}") from exc


def count_in_range(body: str, suffix: str) -> int:
    """Find our suffix in the returned list. Absent means never breached."""
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


def check(password: str, opener=urllib.request.urlopen) -> BreachResult:
    """Look one password up. Never raises: offline is a normal outcome."""
    if not password:
        return BreachResult(checked=False, error="empty password")
    prefix, suffix = split_hash(password)
    try:
        body = fetch_range(prefix, opener=opener)
    except BreachLookupError as exc:
        return BreachResult(checked=False, error=str(exc))
    return BreachResult(checked=True, count=count_in_range(body, suffix))
