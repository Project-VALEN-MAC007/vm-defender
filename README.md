# Adaptive Honeypot — VM-Defender

This repository contains the VM-Defender deliverables for phases D1–D8.  All
host-changing commands are opt-in.  The default mode of every helper is
validation or dry-run so the lab cannot accidentally be exposed to a real
network.

## Current host constraint

The Defender currently has one managed interface, `enp0s3` (`10.0.2.15/24`,
VirtualBox NAT).  The required outer and inner lab interfaces do not exist.
Do not assign `192.168.56.10` or `10.10.10.1` to `enp0s3`.  Add two isolated
VirtualBox adapters first and verify console access before applying D1.

Git, Nginx and conntrack are not installed.  Suricata 7.0.3 and nftables are
installed.  Commands requiring root are collected in
`docs/root-operations.md`; they have not been executed without evidence and a
tested rollback path.

## Safe local verification

```bash
cd "/home/yakult/Documents/Default Project"
python3 -m unittest discover -s tests -v
python3 -m defender.decision_engine.adaptive_defender.cli \
  --config defender/decision_engine/config/lab.json --once --dry-run
python3 tests/generate_pcaps.py
python3 -m tests.run_feedback_loop
```


Live deployment readiness check (read-only):

```bash
python3 -m defender.validation.readiness --pretty
```

Exit code `0` means all live-deploy checks passed. Exit code `2` means the
checker found blockers such as missing lab NICs, packages or inactive services.

Dashboard validation (loopback only):

```bash
python3 -c 'from pathlib import Path; from defender.dashboard.app import serve; serve(Path("evidence/test-results/decisions.jsonl"), Path("evidence/test-results/status.json"))'
```

Do not bind the dashboard to a non-loopback address. The configuration loader
and server both reject that condition.

## WordPress backend

The Defender `wordpress` profile should redirect through
`defender/nginx/adaptive-honeypot.conf.template` to the inner honeypot backend
at `10.10.10.2:8081` with `__WORDPRESS_IP__=10.10.10.2` and
`__WORDPRESS_PORT__=8081`.

See `docs/person1-progress.md` for actual results and phase status.
