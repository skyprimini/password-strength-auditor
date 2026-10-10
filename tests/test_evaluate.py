"""Focused tests for scoring.evaluate.

evaluate is the method everything else in the tool depends on: it turns a
password into a character pool, raw entropy, a set of findings, a compounded
penalty, a 0-4 score, and a list of suggestions. These tests exercise each of
those steps and the paths between them.
"""

import unittest

from pwaudit import scoring
from pwaudit.scoring import SCORE_LABELS, SCORE_THRESHOLDS


class TestEvaluateStructure(unittest.TestCase):
    """The shape of what comes back."""

    def test_returns_a_result(self):
        self.assertIsInstance(scoring.evaluate("anything"), scoring.Result)

    def test_every_field_is_populated(self):
        r = scoring.evaluate("Tr0ub4dor&3")
        self.assertEqual(r.password_length, 11)
        self.assertGreater(r.pool_size, 0)
        self.assertTrue(r.pool_names)
        self.assertGreater(r.raw_entropy, 0)
        self.assertGreaterEqual(r.entropy, 0)
        self.assertIn(r.score, range(5))
        self.assertEqual(r.label, SCORE_LABELS[r.score])
        self.assertIsInstance(r.findings, list)
        self.assertTrue(r.suggestions)

    def test_label_always_matches_score(self):
        for password in ("", "a", "abc123", "password", "7Kq!vlm2-Zt9wRxs"):
            with self.subTest(password=password):
                r = scoring.evaluate(password)
                self.assertEqual(r.label, SCORE_LABELS[r.score])

    def test_length_matches_input(self):
        for password in ("", "a", "ab", "a" * 64):
            with self.subTest(n=len(password)):
                self.assertEqual(scoring.evaluate(password).password_length, len(password))


class TestEvaluateEntropy(unittest.TestCase):
    """Raw entropy, and how penalties reduce it."""

    def test_clean_password_keeps_full_entropy(self):
        r = scoring.evaluate("wZq7-tumbleweed")
        self.assertEqual(r.findings, [])
        self.assertAlmostEqual(r.entropy, r.raw_entropy, places=9)

    def test_penalised_password_loses_entropy(self):
        r = scoring.evaluate("password")
        self.assertTrue(r.findings)
        self.assertLess(r.entropy, r.raw_entropy)

    def test_entropy_never_negative(self):
        # several detectors firing at once must not drive entropy below zero
        r = scoring.evaluate("qwerty1234qwerty1234")
        self.assertGreaterEqual(r.entropy, 0.0)

    def test_penalties_compound_rather_than_sum(self):
        # compounding can approach zero but never cross it, which summing would
        r = scoring.evaluate("aaaaaaaa")
        self.assertGreater(r.entropy, -0.000001)
        self.assertLess(r.entropy, r.raw_entropy)

    def test_longer_clean_password_scores_higher(self):
        short = scoring.evaluate("wZq7-tum")
        longer = scoring.evaluate("wZq7-tumbleweed-xk")
        self.assertLess(short.entropy, longer.entropy)

    def test_wider_character_pool_raises_entropy(self):
        lower = scoring.evaluate("tumbleweedxk")
        mixed = scoring.evaluate("tumbleWeedX7")
        self.assertLess(lower.raw_entropy, mixed.raw_entropy)


class TestEvaluateScoring(unittest.TestCase):
    """The 0-4 banding."""

    def test_empty_password_scores_zero(self):
        r = scoring.evaluate("")
        self.assertEqual(r.score, 0)
        self.assertEqual(r.entropy, 0.0)
        self.assertEqual(r.pool_size, 0)
        self.assertEqual(r.pool_names, [])

    def test_known_weak_passwords_score_at_most_one(self):
        for password in ("password", "123456", "qwerty", "aaaaaaaa", "dragon123"):
            with self.subTest(password=password):
                self.assertLessEqual(scoring.evaluate(password).score, 1)

    def test_known_strong_passwords_score_at_least_three(self):
        for password in ("7Kq!vlm2-Zt9wRxs", "correct-horse-Battery-42!", "wZq7-tumbleweed"):
            with self.subTest(password=password):
                self.assertGreaterEqual(scoring.evaluate(password).score, 3)

    def test_score_rises_with_strength(self):
        weak = scoring.evaluate("password")
        middling = scoring.evaluate("tumbleweed12")
        strong = scoring.evaluate("7Kq!vlm2-Zt9wRxs")
        self.assertLessEqual(weak.score, middling.score)
        self.assertLessEqual(middling.score, strong.score)

    def test_each_threshold_is_reachable(self):
        # a score band that no password can reach would be a bug in the table
        for threshold, expected in SCORE_THRESHOLDS:
            with self.subTest(score=expected):
                self.assertEqual(scoring._score_for(threshold), expected)
                self.assertEqual(scoring._score_for(threshold + 0.5), expected)

    def test_below_lowest_threshold_scores_zero(self):
        lowest = SCORE_THRESHOLDS[-1][0]
        self.assertEqual(scoring._score_for(lowest - 0.1), 0)


class TestEvaluateFindings(unittest.TestCase):
    """What the detectors contribute."""

    def test_findings_are_attached(self):
        kinds = {f.kind for f in scoring.evaluate("password").findings}
        self.assertIn("common", kinds)

    def test_clean_password_has_no_findings(self):
        self.assertEqual(scoring.evaluate("wZq7-tumbleweed").findings, [])

    def test_multiple_detectors_can_fire(self):
        r = scoring.evaluate("qwerty123")
        self.assertGreaterEqual(len(r.findings), 2)


class TestEvaluateSuggestions(unittest.TestCase):
    """Advice is always offered, and matches what was found."""

    def test_always_at_least_one_suggestion(self):
        for password in ("", "a", "password", "7Kq!vlm2-Zt9wRxs"):
            with self.subTest(password=password):
                self.assertTrue(scoring.evaluate(password).suggestions)

    def test_short_password_is_told_to_grow(self):
        tips = " ".join(scoring.evaluate("Ab1!").suggestions).lower()
        self.assertIn("12 characters", tips)

    def test_missing_character_sets_are_named(self):
        tips = " ".join(scoring.evaluate("alllowercaseonly").suggestions).lower()
        self.assertIn("mix in", tips)

    def test_strong_password_gets_positive_advice(self):
        tips = " ".join(scoring.evaluate("7Kq!vlm2-Zt9wRxs").suggestions).lower()
        self.assertIn("password manager", tips)


class TestEvaluateSerialisation(unittest.TestCase):
    def test_as_dict_round_trips_the_important_fields(self):
        d = scoring.evaluate("password").as_dict()
        for key in ("length", "pool_size", "character_sets", "raw_entropy_bits",
                    "entropy_bits", "score", "label", "findings", "suggestions"):
            self.assertIn(key, d)

    def test_findings_serialise_with_their_penalty(self):
        d = scoring.evaluate("password").as_dict()
        self.assertTrue(d["findings"])
        self.assertEqual(set(d["findings"][0]), {"kind", "detail", "penalty"})


if __name__ == "__main__":
    unittest.main()
