"""User-space D8 feedback loop; never reloads the host Suricata service."""
import json
from pathlib import Path
import subprocess
import tempfile

from defender.validation.deploy import staged_deploy
from defender.validation.pipeline import validate

PROJECT = Path(__file__).resolve().parents[1]


def run(command):
    return subprocess.run(command, cwd=PROJECT, capture_output=True, text=True)


def main():
    candidate_path = PROJECT/"tests/fixtures/candidate.json"
    candidate = json.loads(candidate_path.read_text())
    report_path = PROJECT/"evidence/test-results/feedback-loop-report.json"
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); active = root/"local.rules"; active.write_text("")
        validation = validate(candidate_path, active, PROJECT/"tests/fixtures/baseline.json")

        def syntax_test(staging):
            log_dir = root/"syntax"; log_dir.mkdir()
            result = run(["suricata", "-T", "-l", str(log_dir), "-c", "/etc/suricata/suricata.yaml", "-S", str(staging)])
            return result.returncode == 0

        deploy = staged_deploy(candidate, active, root/"backups", root/"registry.jsonl",
                               syntax_test, lambda: True, lambda: True, dry_run=False)
        replay_dir = root/"replay"; replay_dir.mkdir()
        replay = run(["suricata", "-r", "evidence/baseline/http-feedback.pcap", "-l", str(replay_dir),
                      "-c", "/etc/suricata/suricata.yaml", "-S", str(active), "--runmode=single"])
        alerts = [json.loads(line) for line in (replay_dir/"eve.json").read_text().splitlines()
                  if json.loads(line).get("event_type") == "alert"]
        detected = any(item.get("alert", {}).get("signature_id") == candidate["expected_sid"] for item in alerts)
        result = {"evidence": candidate["evidence"], "validation": validation, "deploy": deploy,
                  "replay_exit_code": replay.returncode, "expected_sid": candidate["expected_sid"],
                  "detected_next_attack": detected, "alert_count": len(alerts),
                  "host_service_reloaded": False}
        report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if deploy["status"] == "deployed" and replay.returncode == 0 and detected else 1


if __name__ == "__main__": raise SystemExit(main())
