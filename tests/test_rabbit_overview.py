import unittest

from defender.rabbit_hole.analytics import placement, summarize


def window(sid, depth, steps):
    trail = [{"depth": d, "resource": r, "category": c, "clue_by": by, "clue_confidence": conf,
              "followed_clue": by is not None, "scenario": None} for d, r, c, by, conf in steps]
    return {"family": "web", "protocol": "http", "session_id": sid, "followed": any(s["followed_clue"] for s in trail),
            "duration_seconds": 30.0, "resources": len(trail), "max_depth": depth, "single_access": False,
            "connection_seconds": None, "end_reason": "idle_timeout", "trail": trail}


class RabbitOverviewTest(unittest.TestCase):
    def setUp(self):
        self.items = [
            window("a", 3, [(1, "robots", "recon", None, None), (2, "backup-index", "backup", "jev", .8),
                            (3, "backup-config", "config", "jev", .6)]),
            window("b", 2, [(1, "env", "config", None, None), (2, "admin-login", "admin", "fallback", None)]),
            window("c", 1, [(1, "robots", "recon", None, None)]),
        ]

    def test_placement(self):
        self.assertEqual([placement(i) for i in self.items], ["jev", "fallback", "fixed"])

    def test_by_strategy(self):
        s = summarize(self.items)
        jev = s["by_strategy"]["jev"]
        self.assertEqual(jev["sessions"], 1)
        self.assertEqual(jev["max_depth"], 3)
        self.assertEqual(jev["depth_distribution"], {"3": 1})
        self.assertEqual(jev["average_confidence"], 0.7)
        self.assertEqual(jev["jev_steps"], 2)
        self.assertIsNone(s["by_strategy"]["fixed"]["average_confidence"])
        self.assertEqual(set(s["by_strategy"]), {"jev", "fallback", "fixed"})

    def test_depth_examples(self):
        s = summarize(self.items)
        self.assertEqual(s["depth_examples"]["1"][0], {"resource": "robots", "count": 2, "category": "recon"})
        self.assertEqual(s["depth_examples"]["3"][0]["resource"], "backup-config")

    def test_empty(self):
        s = summarize([])
        self.assertEqual(s["by_strategy"], {})
        self.assertEqual(s["depth_examples"], {})


if __name__ == "__main__":
    unittest.main()
