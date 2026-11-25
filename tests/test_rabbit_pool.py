"""Jev-driven Rabbit Hole: decoy pool, per-session clue choice and the Defender planner."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile
import unittest

from defender.rabbit_hole import pool as pool_mod
from defender.rabbit_hole.config import DEFAULTS, load, validate_raw
from defender.rabbit_hole.planner import Planner
from defender.rabbit_hole.web import WebEngine

ATTACKER = "192.0.2.50"


def write_config(directory: Path, **overrides) -> Path:
    raw = json.loads(json.dumps(DEFAULTS))
    raw.update({"project_root": str(directory), "secret_path": "rabbit.secret", "strategy": "jev"})
    raw["web"]["log_path"] = "web.jsonl"
    raw["web"]["plan_path"] = "plan.json"
    for key, value in overrides.items():
        if isinstance(value, dict):
            raw[key].update(value)
        else:
            raw[key] = value
    path = directory / "rabbit-hole.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class Clock:
    def __init__(self):
        self.value = datetime(2026, 11, 19, 3, 0, tzinfo=timezone.utc).timestamp()

    def __call__(self):
        return self.value


def get(engine, path, ip=ATTACKER, method="GET", body=b"", cookie=None):
    headers = {"X-Real-IP": ip, "User-Agent": "curl/8"}
    if cookie:
        headers["Cookie"] = "PHPSESSID=" + cookie
    return engine.handle(method, path, headers, body, ("127.0.0.1", 40000), ("10.10.10.2", 8084))


def disallowed(text):
    return [line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("Disallow: ") and
            line != "Disallow: /cgi-bin/"]


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load(write_config(self.root))

    def tearDown(self):
        self.tmp.cleanup()

    def test_builtin_pool_is_valid_and_fits_limits(self):
        pool = self.config.pool()
        self.assertGreaterEqual(len(pool.items), 15)
        self.assertEqual(pool.problems(self.config.limits, self.config.organization), [])
        self.assertEqual(self.config.problems(), [])
        backup = pool.items["backup-index"]
        names = {c.id for c in pool.candidates(backup, backup.slots["items"])}
        self.assertIn("backup-config", names)
        self.assertIn("old-exports", names)
        self.assertNotIn("users-export", names)  # grandchild: not directly under /backup/

    def test_invalid_items_are_rejected(self):
        base = {"id": "x", "kind": "file", "category": "config", "path": "/x", "description": "decoy file"}
        with self.assertRaises(pool_mod.PoolError):
            pool_mod.parse_item({**base, "body": "{{clue:missing}}"})
        with self.assertRaises(pool_mod.PoolError):
            pool_mod.parse_item({**base, "category": "malware"})
        with self.assertRaises(pool_mod.PoolError):
            pool_mod.parse_item({**base, "description": ""})
        with self.assertRaises(pool_mod.PoolError):
            pool_mod.parse_item({**base, "kind": "listing", "path": "/x/",
                                 "slots": {"a": {"categories": ["data"]}}})
        with self.assertRaises(ValueError):
            validate_raw({"strategy": "random"})
        self.assertEqual(validate_raw({})["strategy"], "fixed")  # old configs keep the fixed scenarios

    def test_fallback_fills_clues_and_tracks_depth(self):
        engine = WebEngine(self.config, clock=Clock())
        first = get(engine, "/robots.txt")
        sid = first.event["session_id"]
        paths = disallowed(first.body.decode())
        self.assertEqual(len(paths), 2)
        self.assertEqual({c["by"] for c in first.event["clue_choices"]}, {"fallback"})
        followed = get(engine, paths[0], cookie=sid)
        self.assertTrue(followed.event["followed_clue"])
        self.assertEqual((followed.event["clue_from"], followed.event["depth"]), ("robots", 2))
        self.assertEqual(followed.event["clue_by"], "fallback")
        self.assertEqual(followed.event["scenario"], "jev-pool")
        again = get(engine, "/robots.txt", cookie=sid)
        self.assertEqual(disallowed(again.body.decode()), paths)  # frozen for the session

    def test_jev_plan_steers_the_clue_and_is_validated(self):
        plan = {"version": 1, "ips": {ATTACKER: {"choices": {
            "robots.first": {"items": ["admin-login"], "confidence": 0.81},
            "robots.second": {"items": ["users-export"], "confidence": 0.9}}}}}  # users-export: not a candidate
        (self.root / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        engine = WebEngine(self.config, clock=Clock())
        response = get(engine, "/robots.txt")
        paths = disallowed(response.body.decode())
        admin = engine.pool.items["admin-login"].path
        self.assertEqual(paths[0], admin)
        by = {c["slot"]: c for c in response.event["clue_choices"]}
        self.assertEqual((by["first"]["by"], by["first"]["confidence"]), ("jev", 0.81))
        self.assertEqual(by["second"]["by"], "fallback")
        self.assertNotIn(engine.pool.items["users-export"].path, paths)
        login = get(engine, admin, cookie=response.event["session_id"])
        self.assertEqual((login.event["clue_by"], login.event["clue_confidence"]), ("jev", 0.81))
        # Another attacker without a plan gets the fallback.
        other = get(engine, "/robots.txt", ip="198.51.100.7")
        self.assertEqual({c["by"] for c in other.event["clue_choices"]}, {"fallback"})

    def test_listing_and_form_use_chosen_children(self):
        engine = WebEngine(self.config, clock=Clock())
        listing = get(engine, "/backup/")
        links = re.findall(r'<a href="([^"]+)">', listing.body.decode())
        self.assertEqual(len(links) - 1 - 2, 2)  # ../ + 2 fillers + 2 chosen children
        login_path = engine.pool.items["admin-login"].path
        post = get(engine, login_path, method="POST", body=b"username=a&password=b")
        self.assertEqual(post.status, 302)
        self.assertEqual(post.headers["Location"], engine.pool.items["admin-home"].path)

    def test_depth_limit_stops_new_clues(self):
        config = load(write_config(self.root, limits={"max_depth": 1}))
        engine = WebEngine(config, clock=Clock())
        response = get(engine, "/robots.txt")
        self.assertEqual(disallowed(response.body.decode()), [])
        self.assertNotIn("clue_choices", response.event)

    def test_fixed_strategy_keeps_old_scenarios(self):
        config = load(write_config(self.root, strategy="fixed"))
        engine = WebEngine(config, clock=Clock())
        self.assertIsNone(engine.pool)
        self.assertEqual(get(engine, "/robots.txt").event["scenario"], "web-backup-api")


class FakeJev:
    def __init__(self, confidence=0.8):
        self.calls = []
        self.confidence = confidence
        self.has_key = True

    def ask(self, state, questions):
        self.calls.append((state, questions))
        answers = {}
        for name, question in questions.items():
            if name == "goal":
                answers[name] = {"choice": "credential_hunting", "confidence": 0.7}
                continue
            options = list(question["criteria"])
            pick = next((o for o in options if "config" in question["criteria"][o]), options[-1])
            answers[name] = {"choice": pick, "confidence": self.confidence,
                             "probabilities": {o: (0.7 if o == pick else 0.3 / max(1, len(options) - 1)) for o in options}}
        return {"answers": answers}


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load(write_config(self.root, ai={"enabled": True}))
        self.now = datetime(2026, 11, 19, 3, 0, tzinfo=timezone.utc)
        (self.root / "decisions.jsonl").write_text(json.dumps({
            "start_time": (self.now - timedelta(seconds=30)).isoformat(), "source_ip": ATTACKER,
            "protocol": "http", "signature_id": 2008538, "severity": 1, "risk_score": 40.0,
            "action": "redirect_web"}) + "\n", encoding="utf-8")
        (self.root / "eve.json").write_text(json.dumps({
            "event_type": "alert", "timestamp": (self.now - timedelta(seconds=31)).isoformat(), "src_ip": ATTACKER,
            "app_proto": "http", "alert": {"signature_id": 2021070, "signature": "ET INFO Request to Hidden Environment File",
                                           "severity": 2}}) + "\n", encoding="utf-8")
        (self.root / "web.jsonl").write_text("", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def planner(self, client, **kwargs):
        return Planner(self.config, self.root / "decisions.jsonl", [self.root / "eve.json"],
                       [self.root / "web.jsonl"], self.root / "plan.json", client=client,
                       clock=lambda: self.now, **kwargs)

    def test_plan_written_for_redirected_attacker_without_ip_in_state(self):
        fake = FakeJev()
        result = self.planner(fake).run_once()
        self.assertEqual(result["status"], "ok")
        self.assertIn(ATTACKER, result["planned"])
        state, questions = fake.calls[0]
        self.assertNotIn(ATTACKER, state)
        self.assertIn("Hidden Environment File", state)
        self.assertIn("goal", questions)
        plan = json.loads((self.root / "plan.json").read_text())["ips"][ATTACKER]
        self.assertEqual(plan["goal"]["label"], "credential_hunting")
        self.assertIn("robots.first", plan["choices"])
        # The decoy uses the plan for this attacker.
        engine = WebEngine(self.config, clock=Clock())
        response = get(engine, "/robots.txt")
        chosen = {c["slot"]: c for c in response.event["clue_choices"]}
        self.assertEqual(chosen["first"]["by"], "jev")
        self.assertEqual(chosen["first"]["items"], plan["choices"]["robots.first"]["items"])

    def test_same_state_is_not_asked_twice_and_frozen_slots_are_skipped(self):
        fake = FakeJev()
        planner = self.planner(fake)
        planner.run_once()
        planner.run_once()
        self.assertEqual(len(fake.calls), 1)
        engine = WebEngine(self.config, clock=Clock())
        event = get(engine, "/robots.txt").event
        (self.root / "web.jsonl").write_text(json.dumps({**event, "status": 200}) + "\n", encoding="utf-8")
        planner.run_once()
        self.assertEqual(len(fake.calls), 2)
        asked = {q.split(" in ")[0] for q in [v["instructions"] for k, v in fake.calls[1][1].items() if k != "goal"]}
        self.assertFalse(any("/robots.txt" in fake.calls[1][1][k]["instructions"]
                             for k in fake.calls[1][1] if k != "goal"), asked)

    def test_low_confidence_is_left_to_fallback(self):
        self.planner(FakeJev(confidence=0.2)).run_once()
        plan = json.loads((self.root / "plan.json").read_text())["ips"][ATTACKER]
        self.assertEqual(plan["choices"], {})

    def test_disabled_without_key_or_in_fixed_mode(self):
        fake = FakeJev()
        fake.has_key = False
        self.assertEqual(self.planner(fake).run_once()["status"], "missing_api_key")
        fixed = load(write_config(self.root, strategy="fixed", ai={"enabled": True}))
        planner = Planner(fixed, self.root / "decisions.jsonl", [], [], self.root / "plan.json",
                          client=FakeJev(), clock=lambda: self.now)
        self.assertEqual(planner.run_once()["status"], "disabled")
        self.assertFalse((self.root / "plan.json").exists())

    def test_rate_limit_per_ip(self):
        config = load(write_config(self.root, ai={"enabled": True, "plan_max_calls_per_ip_hour": 1}))
        fake = FakeJev()
        planner = Planner(config, self.root / "decisions.jsonl", [], [self.root / "web.jsonl"],
                          self.root / "plan.json", client=fake, clock=lambda: self.now)
        planner.run_once()
        with (self.root / "web.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": "rabbit_hole.web", "source_ip": ATTACKER, "session_id": "s",
                                     "timestamp": self.now.isoformat(), "path": "/x", "status": 404}) + "\n")
        result = planner.run_once()
        self.assertEqual(result["planned"][ATTACKER], {"skipped": "rate_limited"})
        self.assertEqual(len(fake.calls), 1)


class DashboardPoolTests(unittest.TestCase):
    def test_admin_items_validated_and_builtins_protected(self):
        from defender.dashboard.rabbit import RabbitHoleService
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            service = RabbitHoleService(write_config(root), root)
            report = service.pool_catalog()
            self.assertTrue(any(i["id"] == "env" for i in report["items"]))
            with self.assertRaises(ValueError):
                service.save_pool_item({"id": "env", "kind": "file", "category": "config", "path": "/.env2",
                                        "description": "overwrite builtin"})
            item = {"id": "smtp-bak", "kind": "file", "category": "credential", "path": "/backup/smtp.ini.bak",
                    "description": "SMTP settings backup with a password",
                    "body_lines": ["password = {{secret:password:smtp}}", "panel = {{clue:panel}}"],
                    "slots": {"panel": {"categories": ["admin"], "kinds": ["form"]}}}
            service.save_pool_item(item)
            self.assertIn("smtp-bak", {i["id"] for i in service.pool_catalog()["items"]})
            preview = service.pool_preview("smtp-bak")
            self.assertIn("/internal/admin-", preview["content"])
            broken = dict(item, id="bad-item", path="/backup/smtp.ini.bak")  # duplicate path
            with self.assertRaises(ValueError):
                service.save_pool_item(broken)
            self.assertFalse((root / "config/rabbit-hole-pool/bad-item.json").exists())
            service.delete_pool_item("smtp-bak")
            self.assertNotIn("smtp-bak", {i["id"] for i in service.pool_catalog()["items"]})


if __name__ == "__main__":
    unittest.main()
