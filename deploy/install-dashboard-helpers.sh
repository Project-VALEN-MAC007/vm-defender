#!/bin/sh
# Install the pieces that let Dashboard changes take effect on the Defender:
#   1. trap-apply-rules.path/.service  - approved rules are tested with
#      `suricata -T`, installed and reloaded (rollback on failure).
#   2. /var/lib/trap/engine/thresholds.json - thresholds the Dashboard may
#      write; the engine config in /etc stays read-only for the Dashboard.
# Optional: --update-rules installs the repo's et-open-selected.rules through
# the same helper (syntax test, backup, reload, health check).
#
# Run as root on the Defender after syncing the source to $TRAP_ROOT.
# Safe to run again: existing settings are kept, edited files are backed up.
set -eu

TRAP_ROOT="${TRAP_ROOT:-/opt/trap}"
DASH_CONF="${DASH_CONF:-/etc/trap/trap.json}"
ENGINE_CONF="${ENGINE_CONF:-/etc/adaptive-defender/live.json}"
ACTIVE_RULES="${ACTIVE_RULES:-/etc/suricata/rules/et-open-selected.rules}"
SURICATA_CONF="${SURICATA_CONF:-/etc/suricata/suricata.yaml}"
APPLY_DIR=/var/lib/trap/rules
ENGINE_STATE=/var/lib/trap/engine
THRESHOLDS="$ENGINE_STATE/thresholds.json"
DASH_USER="${DASH_USER:-trap-dashboard}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
UPDATE_RULES=0
[ "${1:-}" = "--update-rules" ] && UPDATE_RULES=1

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
for f in "$DASH_CONF" "$ENGINE_CONF" "$ACTIVE_RULES" "$SURICATA_CONF" \
         "$TRAP_ROOT/defender/suricata/apply_rules.py"; do
  [ -e "$f" ] || { echo "missing: $f (set the matching variable)" >&2; exit 1; }
done
id "$DASH_USER" >/dev/null 2>&1 || { echo "missing user: $DASH_USER" >&2; exit 1; }

echo "== state directories"
install -d -o "$DASH_USER" -g "$DASH_USER" -m 0750 "$APPLY_DIR" "$ENGINE_STATE"

echo "== back up configs (*.bak.$STAMP)"
cp -p "$DASH_CONF" "$DASH_CONF.bak.$STAMP"
cp -p "$ENGINE_CONF" "$ENGINE_CONF.bak.$STAMP"

echo "== Dashboard config: rules.apply_dir"
python3 - "$DASH_CONF" "$APPLY_DIR" <<'PY'
import json, os, sys
path, apply_dir = sys.argv[1], sys.argv[2]
config = json.load(open(path, encoding="utf-8"))
config.setdefault("rules", {})["apply_dir"] = apply_dir
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2); stream.write("\n")
os.chmod(tmp, os.stat(path).st_mode & 0o7777)
os.chown(tmp, os.stat(path).st_uid, os.stat(path).st_gid)
os.replace(tmp, path)
PY

echo "== engine config: thresholds_path, scan_only_signatures; seed thresholds file"
python3 - "$ENGINE_CONF" "$THRESHOLDS" <<'PY'
import json, os, sys
path, thresholds_path = sys.argv[1], sys.argv[2]
config = json.load(open(path, encoding="utf-8"))
config["thresholds_path"] = thresholds_path
config.setdefault("scan_only_signatures", [2017616])
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2); stream.write("\n")
os.chmod(tmp, os.stat(path).st_mode & 0o7777)
os.chown(tmp, os.stat(path).st_uid, os.stat(path).st_gid)
os.replace(tmp, path)
if not os.path.exists(thresholds_path):
    with open(thresholds_path, "w", encoding="utf-8") as stream:
        json.dump({"thresholds": config["thresholds"]}, stream, indent=2); stream.write("\n")
PY
chown "$DASH_USER:$DASH_USER" "$THRESHOLDS"; chmod 0640 "$THRESHOLDS"

echo "== rule apply units"
sed -e "s#/opt/trap#$TRAP_ROOT#g" \
    -e "s#--active [^ ]*#--active $ACTIVE_RULES#" \
    -e "s#--suricata-config [^ ]*#--suricata-config $SURICATA_CONF#" \
    "$TRAP_ROOT/defender/suricata/systemd/trap-apply-rules.service" \
    > /etc/systemd/system/trap-apply-rules.service
cp "$TRAP_ROOT/defender/suricata/systemd/trap-apply-rules.path" /etc/systemd/system/trap-apply-rules.path
systemd-analyze verify /etc/systemd/system/trap-apply-rules.service /etc/systemd/system/trap-apply-rules.path
systemctl daemon-reload
systemctl enable --now trap-apply-rules.path

if [ "$UPDATE_RULES" -eq 1 ]; then
  echo "== install repo rules through the helper"
  install -o "$DASH_USER" -g "$DASH_USER" -m 0640 \
    "$TRAP_ROOT/defender/suricata/rules/et-open-selected.rules" "$APPLY_DIR/pending.rules"
  python3 "$TRAP_ROOT/defender/suricata/apply_rules.py" --apply-dir "$APPLY_DIR" \
    --active "$ACTIVE_RULES" --suricata-config "$SURICATA_CONF"
fi

echo "== restart engine and Dashboard"
systemctl restart adaptive-defender trap-dashboard
sleep 2
systemctl is-active adaptive-defender trap-dashboard trap-apply-rules.path suricata
echo "done. backups: $DASH_CONF.bak.$STAMP $ENGINE_CONF.bak.$STAMP"
