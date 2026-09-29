"""Tests for the HTML report."""

import os
import tempfile
import unittest

from pwaudit import batch, report


def rows_from(lines):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    try:
        return batch.audit_file(path)
    finally:
        os.remove(path)


SAMPLE = [
    "email:password",
    "banking:7Kq!vlm2-Zt9wRxs",
    "laptop:qwerty123",
]


class TestRender(unittest.TestCase):
    def setUp(self):
        self.rows = rows_from(SAMPLE)
        self.html = report.render(self.rows)

    def test_is_a_complete_document(self):
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", self.html)

    def test_passwords_are_never_written(self):
        for secret in ("password", "7Kq!vlm2-Zt9wRxs", "qwerty123"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, self.html)

    def test_labels_are_present(self):
        for label in ("email", "banking", "laptop"):
            self.assertIn(label, self.html)

    def test_is_self_contained(self):
        # no external stylesheets, scripts, or images
        self.assertNotIn("<link", self.html)
        self.assertNotIn("src=", self.html)
        self.assertIn("<style>", self.html)
        self.assertIn("<script>", self.html)

    def test_summary_counts_shown(self):
        self.assertIn("audited", self.html)
        self.assertIn(str(len(self.rows)), self.html)

    def test_every_row_rendered(self):
        self.assertEqual(self.html.count("<tr>"), len(self.rows) + 1)  # +1 header

    def test_table_is_sortable(self):
        self.assertIn("data-key", self.html)
        self.assertIn("aria-sort", self.html)

    def test_labels_are_escaped(self):
        rows = rows_from(["<script>alert(1)</script>:hunter2"])
        out = report.render(rows)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_empty_audit_still_renders(self):
        out = report.render([])
        self.assertIn("</html>", out)


class TestWrite(unittest.TestCase):
    def test_writes_a_file(self):
        rows = rows_from(SAMPLE)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            report.write(rows, path)
            self.assertTrue(os.path.exists(path))
            content = open(path, encoding="utf-8").read()
            self.assertIn("</html>", content)
            self.assertNotIn("qwerty123", content)


if __name__ == "__main__":
    unittest.main()
