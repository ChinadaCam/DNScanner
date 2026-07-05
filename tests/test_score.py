import unittest

from DNScanner.score import compute_score, grade_for


class TestScore(unittest.TestCase):
    def test_clean_is_a_plus(self):
        r = compute_score({"findings": [{"severity": "info"}, {"severity": "info"}]})
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["grade"], "A+")

    def test_high_penalised(self):
        r = compute_score({"findings": [{"severity": "high"}]})
        self.assertEqual(r["score"], 65)
        self.assertEqual(r["grade"], "D")

    def test_medium_blocks_a_plus(self):
        r = compute_score({"findings": [{"severity": "medium"}]})
        self.assertEqual(r["score"], 85)
        self.assertEqual(r["grade"], "B")

    def test_low_is_light(self):
        # lows cost little (2 each); a high dominates the score
        r = compute_score({"findings": [{"severity": "high"}, {"severity": "low"}, {"severity": "low"}]})
        self.assertEqual(r["score"], 100 - 35 - 4)
        self.assertEqual(r["breakdown"], {"high": 1, "medium": 0, "low": 2, "info": 0})
        self.assertEqual(r["grade"], "D")

    def test_many_lows_are_capped(self):
        # a long tail of low findings cannot sink the grade (combined cap = 10)
        r = compute_score({"findings": [{"severity": "low"}] * 20})
        self.assertEqual(r["score"], 90)          # 20*2=40, capped at 10
        self.assertEqual(r["grade"], "A")

    def test_lows_do_not_outweigh_a_medium(self):
        # six lows (capped at 10) weigh less than nothing compared to the 15 for a medium
        lows = compute_score({"findings": [{"severity": "low"}] * 6})["score"]
        medium = compute_score({"findings": [{"severity": "medium"}]})["score"]
        self.assertGreater(lows, medium)          # 90 > 85

    def test_grade_boundaries(self):
        self.assertEqual(grade_for(95, {}), "A+")
        self.assertEqual(grade_for(95, {"high": 1}), "A")   # A+ blocked by a high finding
        self.assertEqual(grade_for(90, {}), "A")
        self.assertEqual(grade_for(59, {}), "F")


if __name__ == "__main__":
    unittest.main()
