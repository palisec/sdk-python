import unittest

from palisec.mandates import tally, vote_typed_data

E18 = 10**18


class MandateTests(unittest.TestCase):
    def test_vote_typed_data(self):
        td = vote_typed_data(4663, "demo", "p1", "for", 123)
        self.assertEqual(td["message"], {"mandate": "demo", "proposalId": "p1", "choice": 0, "snapshotBlock": 123})
        with self.assertRaises(ValueError):
            vote_typed_data(4663, "demo", "p1", "maybe", 1)

    def test_tally_edges(self):
        q = str(1000 * E18)
        self.assertTrue(tally(q, 5000, [{"choice": "for", "weight": str(1000 * E18)}])["quorum_reached"])
        self.assertFalse(tally(q, 5000, [{"choice": "for", "weight": str(1000 * E18 - 1)}])["quorum_reached"])
        self.assertFalse(tally(q, 5000, [{"choice": "for", "weight": str(600 * E18)}, {"choice": "against", "weight": str(600 * E18)}])["passed"])
        self.assertTrue(tally(q, 5000, [{"choice": "for", "weight": str(600 * E18 + 1)}, {"choice": "against", "weight": str(600 * E18)}])["passed"])


if __name__ == "__main__":
    unittest.main()
