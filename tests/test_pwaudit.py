"""Tests for the scoring engine, detectors, and crack-time estimates.

Run with: python -m unittest discover -s tests
"""

import unittest

from pwaudit import crack_time, patterns, scoring


class TestCharacterPool(unittest.TestCase):
    def test_lowercase_only(self):
        size, names = scoring.character_pool("abcdef")
        self.assertEqual(size, 26)
        self.assertEqual(names, ["lowercase"])

    def test_all_four_sets(self):
        size, names = scoring.character_pool("aA1!")
        self.assertEqual(size, 26 + 26 + 10 + 33)
        self.assertEqual(len(names), 4)

    def test_empty_password_has_no_pool(self):
        size, names = scoring.character_pool("")
        self.assertEqual(size, 0)
        self.assertEqual(names, [])


class TestRawEntropy(unittest.TestCase):
    def test_grows_with_length(self):
        self.assertLess(scoring.raw_entropy("abcd"), scoring.raw_entropy("abcdefgh"))

    def test_grows_with_pool_size(self):
        self.assertLess(scoring.raw_entropy("abcdefgh"), scoring.raw_entropy("abcdefG1"))

    def test_empty_is_zero(self):
        self.assertEqual(scoring.raw_entropy(""), 0.0)


class TestDetectors(unittest.TestCase):
    def test_common_password_is_flagged(self):
        self.assertIsNotNone(patterns.find_common_password("password"))

    def test_leet_substitution_is_flagged(self):
        self.assertIsNotNone(patterns.find_common_password("p@ssw0rd"))

    def test_common_word_with_suffix_is_flagged(self):
        self.assertIsNotNone(patterns.find_common_password("dragon123"))

    def test_uncommon_password_is_not_flagged(self):
        self.assertIsNone(patterns.find_common_password("wZq7-tumbleweed"))

    def test_ascending_sequence(self):
        self.assertIsNotNone(patterns.find_sequence("abcd"))

    def test_descending_sequence(self):
        self.assertIsNotNone(patterns.find_sequence("4321"))

    def test_short_run_is_ignored(self):
        self.assertIsNone(patterns.find_sequence("ab"))

    def test_repeated_character(self):
        self.assertIsNotNone(patterns.find_repeat("aaaa"))

    def test_repeated_block(self):
        self.assertIsNotNone(patterns.find_repeat("abcabc"))

    def test_keyboard_walk(self):
        self.assertIsNotNone(patterns.find_keyboard_walk("qwerty"))

    def test_year_is_flagged(self):
        self.assertIsNotNone(patterns.find_date("summer1998"))

    def test_leet_normalisation(self):
        self.assertEqual(patterns.normalise_leet("P@ssw0rd"), "password")


class TestEvaluate(unittest.TestCase):
    def test_known_weak_scores_low(self):
        for weak in ("password", "123456", "qwerty", "aaaaaaaa"):
            with self.subTest(password=weak):
                self.assertLessEqual(scoring.evaluate(weak).score, 1)

    def test_known_strong_scores_high(self):
        for strong in ("7Kq!vlm2-Zt9wRxs", "correct-horse-Battery-42!"):
            with self.subTest(password=strong):
                self.assertGreaterEqual(scoring.evaluate(strong).score, 3)

    def test_penalties_reduce_entropy(self):
        result = scoring.evaluate("password")
        self.assertLess(result.entropy, result.raw_entropy)

    def test_clean_password_keeps_its_entropy(self):
        result = scoring.evaluate("wZq7-tumbleweed")
        self.assertAlmostEqual(result.entropy, result.raw_entropy, places=6)

    def test_suggestions_are_always_present(self):
        self.assertTrue(scoring.evaluate("password").suggestions)
        self.assertTrue(scoring.evaluate("7Kq!vlm2-Zt9wRxs").suggestions)

    def test_result_serialises(self):
        data = scoring.evaluate("password").as_dict()
        self.assertIn("score", data)
        self.assertIn("findings", data)

    def test_empty_password(self):
        result = scoring.evaluate("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.entropy, 0.0)


class TestCrackTime(unittest.TestCase):
    def test_more_entropy_takes_longer(self):
        weak = crack_time.guesses_for(20)
        strong = crack_time.guesses_for(60)
        self.assertLess(weak, strong)

    def test_all_scenarios_returned(self):
        self.assertEqual(len(crack_time.estimate_all(40)), len(crack_time.SCENARIOS))

    def test_zero_entropy_is_instant(self):
        estimates = crack_time.estimate_all(0)
        self.assertEqual(estimates[0].human, "instantly")

    def test_very_large_entropy_does_not_overflow(self):
        estimates = crack_time.estimate_all(4096)
        self.assertTrue(all(e.seconds > 0 for e in estimates))

    def test_humanise_boundaries(self):
        self.assertEqual(crack_time.humanise(0.5), "instantly")
        self.assertIn("seconds", crack_time.humanise(30))
        self.assertIn("minutes", crack_time.humanise(600))
        self.assertIn("years", crack_time.humanise(crack_time.YEAR * 5))

    def test_humanise_uses_singular_for_one(self):
        self.assertEqual(crack_time.humanise(1), "1 second")
        self.assertEqual(crack_time.humanise(crack_time.MINUTE), "1 minute")
        self.assertEqual(crack_time.humanise(crack_time.HOUR), "1 hour")
        self.assertEqual(crack_time.humanise(crack_time.YEAR), "1 year")
        self.assertEqual(crack_time.humanise(crack_time.CENTURY), "1 century")


if __name__ == "__main__":
    unittest.main()
