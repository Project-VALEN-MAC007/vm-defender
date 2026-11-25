#!/bin/sh
# Run on the Defender every minute (cron or systemd timer).
# Pushes Rabbit Hole settings edited in the Dashboard to the Honeypot,
# and pulls Honeypot logs back so the Dashboard can read them.
set -eu
HONEYPOT="${TRAP_HONEYPOT:-trapsync@10.10.10.2}"
KEY="${TRAP_SYNC_KEY:-/etc/trap/trapsync_ed25519}"
SSH="ssh -i $KEY -o BatchMode=yes -o StrictHostKeyChecking=yes"
PLAN=/var/lib/trap/rabbit-hole-plan.json

# "trap-sync.sh plan": push only the Jev clue plan, called by the planner right after it changes.
if [ "${1:-}" = "plan" ]; then
  [ -f "$PLAN" ] && rsync -t -e "$SSH" "$PLAN" "$HONEYPOT:$PLAN"
  # The Cowrie container only sees /var/lib/trap/cowrie-fs (read-only).
  [ -f "$PLAN" ] && rsync -t -e "$SSH" "$PLAN" "$HONEYPOT:/var/lib/trap/cowrie-fs/rabbit-hole-plan.json"
  exit 0
fi

rsync -t -e "$SSH" /var/lib/trap/rabbit-hole.json "$HONEYPOT:/var/lib/trap/rabbit-hole.json"
rsync -rt --delete --exclude .backups -e "$SSH" /var/lib/trap/rabbit-hole-scenarios/ "$HONEYPOT:/var/lib/trap/rabbit-hole-scenarios/"
rsync -rt --delete --exclude .backups -e "$SSH" /var/lib/trap/rabbit-hole-pool/ "$HONEYPOT:/var/lib/trap/rabbit-hole-pool/" 2>/dev/null || true
[ -f "$PLAN" ] && rsync -t -e "$SSH" "$PLAN" "$HONEYPOT:$PLAN" || true
[ -f "$PLAN" ] && rsync -t -e "$SSH" "$PLAN" "$HONEYPOT:/var/lib/trap/cowrie-fs/rabbit-hole-plan.json" || true

mkdir -p /var/log/trap/honeypot
rsync -t --append-verify -e "$SSH" \
  "$HONEYPOT:/var/log/trap/rabbit-hole-web.jsonl" \
  "$HONEYPOT:/var/log/cowrie/cowrie.json" \
  "$HONEYPOT:/var/log/cowrie/trap-rabbit-shell.jsonl" \
  /var/log/trap/honeypot/ || true
# SNARE/TANNER web honeypot requests (TANNER writes them through the compose volume).
rsync -t --append-verify -e "$SSH" \
  "$HONEYPOT:/opt/trap/honeypot/snare-tanner/data/tanner/events.jsonl" \
  /var/log/trap/honeypot/tanner-events.jsonl || true
chmod 0640 /var/log/trap/honeypot/* 2>/dev/null || true
