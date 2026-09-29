"""Tests for the breach lookup.

Every test uses a fake opener, so the suite never touches the network and
still passes offline.
"""

import io
import unittest
import urllib.error

from pwaudit import breach


class FakeResponse(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def opener_returning(body):
    def _open(request, timeout=None):
        return FakeResponse(body.encode("utf-8"))
    return _open


def opener_raising(exc):
    def _open(request, timeout=None):
        raise exc
    return _open


class TestHashSplit(unittest.TestCase):
    def test_known_sha1_prefix(self):
        # SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        prefix, suffix = breach.split_hash("password")
        self.assertEqual(prefix, "5BAA6")
        self.assertEqual(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")

    def test_only_five_characters_are_sent(self):
        prefix, _ = breach.split_hash("anything at all")
        self.assertEqual(len(prefix), 5)

    def test_prefix_and_suffix_reassemble(self):
        prefix, suffix = breach.split_hash("hunter2")
        self.assertEqual(len(prefix + suffix), 40)


class TestCountInRange(unittest.TestCase):
    def test_finds_matching_suffix(self):
        _, suffix = breach.split_hash("password")
        body = f"0000000000000000000000000000000000:5\r\n{suffix}:12345\r\n"
        self.assertEqual(breach.count_in_range(body, suffix), 12345)

    def test_absent_suffix_counts_zero(self):
        self.assertEqual(breach.count_in_range("ABC:5\r\nDEF:9\r\n", "ZZZ"), 0)

    def test_malformed_count_is_zero(self):
        self.assertEqual(breach.count_in_range("ABC:notanumber", "ABC"), 0)

    def test_empty_body(self):
        self.assertEqual(breach.count_in_range("", "ABC"), 0)


class TestCheck(unittest.TestCase):
    def test_breached_password(self):
        _, suffix = breach.split_hash("password")
        result = breach.check("password", opener=opener_returning(f"{suffix}:9999\r\n"))
        self.assertTrue(result.checked)
        self.assertTrue(result.breached)
        self.assertEqual(result.count, 9999)

    def test_clean_password(self):
        result = breach.check("wZq7-tumbleweed", opener=opener_returning("AAAA:1\r\n"))
        self.assertTrue(result.checked)
        self.assertFalse(result.breached)

    def test_offline_is_not_an_error(self):
        result = breach.check("password", opener=opener_raising(urllib.error.URLError("offline")))
        self.assertFalse(result.checked)
        self.assertFalse(result.breached)
        self.assertIn("could not reach", result.error)

    def test_empty_password_is_not_looked_up(self):
        result = breach.check("", opener=opener_returning("should not be used"))
        self.assertFalse(result.checked)

    def test_summary_wording(self):
        _, suffix = breach.split_hash("password")
        once = breach.check("password", opener=opener_returning(f"{suffix}:1\r\n"))
        self.assertEqual(once.summary(), "found once in the breach corpus")
        clean = breach.check("password", opener=opener_returning("AAAA:1\r\n"))
        self.assertEqual(clean.summary(), "not found in the breach corpus")

    def test_serialises(self):
        result = breach.check("password", opener=opener_returning("AAAA:1\r\n"))
        self.assertEqual(set(result.as_dict()), {"checked", "breached", "count", "error"})


if __name__ == "__main__":
    unittest.main()
