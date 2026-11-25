#!/bin/bash
# Fix ownership that logrotate/engine leave behind, so the Dashboard (trap-dashboard)
# and the Jev planner can read decisions.jsonl after a reboot.
set -euo pipefail
chgrp trap-dashboard /var/log/adaptive-defender/decisions.jsonl
chmod 0640 /var/log/adaptive-defender/decisions.jsonl
# The web decoy runs as uid 995 (traprabbit) inside the container and must read the plan.
chmod 0644 /var/lib/trap/rabbit-hole-plan.json 2>/dev/null || true
chmod 0644 /var/lib/trap/cowrie-fs/rabbit-hole-plan.json 2>/dev/null || true
echo "permissions fixed"
