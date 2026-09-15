# Interface contract requested from person 2

No endpoint below is assumed active until person 2 returns observed values and
Defender verifies them over the isolated inner network.

```json
{
  "schema_version": "1.0",
  "honeypot": {
    "observed_ip": "REQUIRED",
    "interface": "REQUIRED",
    "return_route_via": "REQUIRED"
  },
  "profiles": {
    "wordpress": {"port": "REQUIRED", "health_path": "REQUIRED", "expected_status": "REQUIRED"},
    "phpmyadmin": {"port": "REQUIRED", "health_path": "REQUIRED", "expected_status": "REQUIRED"},
    "cowrie": {"port": 2222, "ip": "10.10.10.2", "health_method": "REQUIRED", "json_log_path": "REQUIRED"},
    "telnet": {"port": "REQUIRED", "ip": "REQUIRED", "health_method": "REQUIRED", "json_log_path": "REQUIRED"}
  },
  "candidate_rule": {
    "rule_id": "REQUIRED",
    "version": "REQUIRED",
    "status": "candidate",
    "evidence": "REDACTED_REFERENCE_REQUIRED",
    "confidence": 0.0,
    "reviewer": "REQUIRED",
    "expected_sid": 2200401,
    "rule": "REQUIRED",
    "test_pcap": "REQUIRED",
    "quality_report": "REQUIRED"
  }
}
```

Normalized event exchange fields are `timestamp`, `source_ip`,
`destination_port`, `protocol`, `signature_id`, `severity`, `risk_score`,
`profile_id`, `action`, and `reason`. Timestamps must include an offset and all
three VM clocks must be NTP-synchronized.
