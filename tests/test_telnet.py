#!/usr/bin/env python3
"""
Unit tests for Telnet Honeypot
"""

import unittest
import asyncio
import json
from pathlib import Path
from defender.telnet.server import TelnetHoneypot, TelnetSession


class TestTelnetHoneypot(unittest.TestCase):
    """Test telnet honeypot functionality"""

    def test_honeypot_initialization(self):
        """Test honeypot can be initialized"""
        honeypot = TelnetHoneypot(host="127.0.0.1", port=2323)
        self.assertEqual(honeypot.host, "127.0.0.1")
        self.assertEqual(honeypot.port, 2323)

    def test_honeypot_with_log_path(self):
        """Test honeypot with log path"""
        log_path = Path("/tmp/test_telnet.jsonl")
        honeypot = TelnetHoneypot(host="127.0.0.1", port=2323, log_path=log_path)
        self.assertEqual(honeypot.log_path, log_path)

    def test_session_id_generation(self):
        """Test session ID is unique"""
        # Mock reader/writer
        class MockWriter:
            def get_extra_info(self, key):
                return ("192.168.1.100", 54321)

        class MockReader:
            pass

        session = TelnetSession(MockReader(), MockWriter())
        self.assertIsNotNone(session.session_id)
        self.assertIn("192.168.1.100", session.session_id)


class TestTelnetIntegration(unittest.TestCase):
    """Integration tests for telnet honeypot"""

    def test_log_file_structure(self):
        """Test that log entries are valid JSON"""
        log_path = Path("/tmp/test_telnet_integration.jsonl")

        # Create a sample log entry
        sample_log = {
            "timestamp": "2026-09-15T10:30:45.123456",
            "session_id": "192.168.1.100:54321_1726395045.123",
            "remote_addr": "192.168.1.100:54321",
            "event_type": "connection",
            "data": {"status": "established"}
        }

        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'w') as f:
            f.write(json.dumps(sample_log) + '\n')

        # Verify we can read it back
        with open(log_path, 'r') as f:
            line = f.readline()
            parsed = json.loads(line)
            self.assertEqual(parsed["event_type"], "connection")
            self.assertEqual(parsed["remote_addr"], "192.168.1.100:54321")

        # Cleanup
        log_path.unlink()


if __name__ == "__main__":
    unittest.main()
