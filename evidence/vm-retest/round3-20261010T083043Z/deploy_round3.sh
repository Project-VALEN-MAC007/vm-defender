set -euo pipefail
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=/var/lib/trap/retests/round3-$STAMP
mkdir -p "$D/baseline"
date -u +%FT%TZ > "$D/test-start.txt"
printf '%s' "$D" > /var/lib/trap/current-retest-dir
tar -czf "$D/baseline/source.tar.gz" -C /opt/trap .
cp /etc/nginx/conf.d/trap.conf "$D/baseline/nginx-trap.conf"
cp /etc/adaptive-defender/live.json /var/lib/trap/engine/thresholds.json "$D/baseline/"
systemctl stop adaptive-defender
tar -xf /tmp/trap-new-source.tar -C /opt/trap
cd /opt/trap
python3 -m unittest discover -s tests > "$D/unit-tests.txt" 2>&1 || { cat "$D/unit-tests.txt"; systemctl start adaptive-defender; exit 1; }
cat "$D/unit-tests.txt"
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nginx/conf.d/trap.conf');s=p.read_text();s=s.replace('"timestamp":"$time_iso8601",','"timestamp":"$time_iso8601","msec":"$msec","worker_pid":"$pid",');p.write_text(s)
PY
nginx -t
systemctl reload nginx
systemctl restart adaptive-defender
systemctl show adaptive-defender -p User -p ProtectProc -p ProcSubset > "$D/proc-access.txt"
cat "$D/proc-access.txt"
test -s /run/nginx.pid
python3 - <<'PY' | tee "$D/nginx-workers.json"
from defender.decision_engine.adaptive_defender.engine import NginxReloader
import json
r=NginxReloader();master=r._master();workers=r._workers(master)
assert master and workers
print(json.dumps({'master':master,'workers':workers}))
PY
systemctl is-active adaptive-defender nginx suricata trap-dashboard
printf 'RETEST_DIR=%s\n' "$D"
