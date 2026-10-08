#!/bin/sh
# Run on the Defender every minute (cron or systemd timer).
# Pushes Rabbit Hole settings edited in the Dashboard to the Honeypot,
# and pulls Honeypot logs back so the Dashboard can read them.
set -eu
HONEYPOT="${TRAP_HONEYPOT:-trapsync@10.10.10.2}"
KEY="${TRAP_SYNC_KEY:-/etc/trap/trapsync_ed25519}"
SSH="ssh -i $KEY -o BatchMode=yes -o StrictHostKeyChecking=yes"

rsync -t -e "$SSH" /var/lib/trap/rabbit-hole.json "$HONEYPOT:/var/lib/trap/rabbit-hole.json"
rsync -rt --delete --exclude .backups -e "$SSH" /var/lib/trap/rabbit-hole-scenarios/ "$HONEYPOT:/var/lib/trap/rabbit-hole-scenarios/"

mkdir -p /var/log/trap/honeypot
rsync -t --append-verify -e "$SSH" \
  "$HONEYPOT:/var/log/trap/rabbit-hole-web.jsonl" \
  "$HONEYPOT:/var/log/cowrie/cowrie.json" \
  /var/log/trap/honeypot/ || true
# SNARE/TANNER web honeypot requests (TANNER writes them through the compose volume).
rsync -t --append-verify -e "$SSH" \
  "$HONEYPOT:/opt/trap/honeypot/snare-tanner/data/tanner/events.jsonl" \
  /var/log/trap/honeypot/tanner-events.jsonl || true
chmod 0640 /var/log/trap/honeypot/* 2>/dev/null || true
