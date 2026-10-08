from pathlib import Path
import unittest

from defender.decision_engine.adaptive_defender.adapters import NginxMapAdapter
from defender.decision_engine.adaptive_defender.config import load_settings
from defender.decision_engine.adaptive_defender.models import Event
from defender.decision_engine.adaptive_defender.risk import RiskEngine
from tests.test_decision_engine import raw_event


class SnareProfileTests(unittest.TestCase):
    def test_shipped_configs_route_web_to_available_nginx_profile(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / 'defender/nginx/adaptive-honeypot.conf.template').read_text()
        generated = (root / 'defender/nginx/generated/adaptive-honeypot.http.conf').read_text()
        for name in ('lab', 'live'):
            settings = load_settings(root / 'defender/decision_engine/config' / (name + '.json'))
            engine = RiskEngine(settings.thresholds, settings.decay_per_minute,
                                settings.expiry_seconds, web_profile=settings.web_profile)
            decision = engine.decide(Event.from_eve(raw_event(protocol='http')))
            self.assertEqual(decision.profile, 'snare')
            self.assertIn('192.0.2.20 snare;', NginxMapAdapter(Path('unused')).render(
                {decision.source_ip: decision.profile}))
            self.assertIn('snare       http://__SNARE_IP__:__SNARE_PORT__;', template)
            self.assertIn('snare       http://10.10.10.2:8083;', generated)
        self.assertTrue(load_settings(root / 'defender/decision_engine/config/lab.json').dry_run)

    def test_snare_redirect_and_remote_shell_profiles(self):
        for protocol, profile in [('http', 'snare'), ('ssh', 'cowrie'), ('telnet', 'cowrie')]:
            engine = RiskEngine({'monitor': 15, 'redirect': 40, 'temporary_block': 80},
                                1, 1800, web_profile='snare')
            decision = engine.decide(Event.from_eve(raw_event(protocol=protocol)))
            self.assertEqual(decision.profile, profile)
            if protocol == 'http':
                self.assertIn('192.0.2.20 snare;', NginxMapAdapter(Path('unused')).render(
                    {decision.source_ip: decision.profile}))

    def test_reject_unknown_profile(self):
        with self.assertRaises(ValueError):
            RiskEngine({}, 1, 1800, web_profile='unknown')
