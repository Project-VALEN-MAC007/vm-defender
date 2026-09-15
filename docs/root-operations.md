# Root operations runbook

These commands are intentionally not automatic.  Execute them only from the
local VirtualBox console after the two isolated lab NICs exist.

## Pre-change capture

```bash
sudo mkdir -p /root/vm-defender-backup
sudo cp -a /etc/netplan /root/vm-defender-backup/netplan
sudo cp -a /etc/NetworkManager/system-connections /root/vm-defender-backup/system-connections
sudo nft list ruleset | sudo tee /root/vm-defender-backup/nftables.before.nft
sudo sysctl net.ipv4.ip_forward | sudo tee /root/vm-defender-backup/ip-forward.before.txt
ip -br link
ip -br addr
ip route
```

Keep the GUI console open.  Schedule a recovery before applying network state:

```bash
sudo systemd-run --unit defender-network-rollback --on-active=3m \
  /bin/sh -c 'cp -a /root/vm-defender-backup/netplan/. /etc/netplan/; netplan apply; nft -f /root/vm-defender-backup/nftables.before.nft'
```

Cancel only after console and management connectivity are verified:

```bash
sudo systemctl stop defender-network-rollback.timer
```

## Package installation (requires sudo password)

```bash
sudo apt update
sudo apt install --no-install-recommends git nginx conntrack
```

## Optional WordPress backend packages

The Defender `wordpress` profile should point at the inner honeypot backend
`10.10.10.2:8081`. If Docker is not installed on the honeypot VM, install
Docker Engine and the Compose plugin from the approved package source for this
lab, then start the backend there:

```bash
cd "/home/yakult/Desktop/Default Project/wordpress"
cp .env.example .env
$EDITOR .env
docker compose up -d
curl -fsS http://127.0.0.1:8081/wp-login.php
```

From VM-Defender, verify the routed backend before activating Nginx:

```bash
curl -fsS http://10.10.10.2:8081/wp-login.php
```

## Suricata host activation

Back up first, copy only a config that passed `suricata -T`, then restart and
check `eve.json`.  Never overwrite `/etc/suricata/suricata.yaml` in place.

```bash
sudo cp -a /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak.$(date -u +%Y%m%dT%H%M%SZ)
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl --no-pager --full status suricata
sudo test -s /var/log/suricata/eve.json
```

## Emergency recovery

From the VirtualBox console:

```bash
sudo cp -a /root/vm-defender-backup/netplan/. /etc/netplan/
sudo netplan generate
sudo netplan apply
sudo nft flush table inet adaptive_defender 2>/dev/null || true
sudo nft -f /root/vm-defender-backup/nftables.before.nft
sudo sysctl -w net.ipv4.ip_forward=0
```

## Live redirect automation

Deploy the live Nginx map, site, config and decision engine service after reviewing the generated files:

```bash
sudo mkdir -p /etc/nginx/maps /etc/adaptive-defender /var/lib/adaptive-defender /var/log/adaptive-defender /opt/adaptive-honeypot
sudo cp -a "/home/yakult/Desktop/Default Project/." /opt/adaptive-honeypot/
sudo install -d -m 0750 /etc/adaptive-defender/tls
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout /etc/adaptive-defender/tls/defender.lab.key \
  -out /etc/adaptive-defender/tls/defender.lab.crt \
  -subj "/CN=defender.lab"
sudo chmod 0640 /etc/adaptive-defender/tls/defender.lab.key
sudo chmod 0644 /etc/adaptive-defender/tls/defender.lab.crt
sudo sh -c 'printf "%s\n" "# generated atomically; do not edit" "default real;" > /etc/nginx/maps/redirect_map.conf'
sudo cp "/opt/adaptive-honeypot/defender/nginx/generated/adaptive-honeypot.http.conf" /etc/nginx/sites-available/adaptive-honeypot
sudo ln -sf /etc/nginx/sites-available/adaptive-honeypot /etc/nginx/sites-enabled/adaptive-honeypot
sudo rm -f /etc/nginx/sites-enabled/default
sudo cp /opt/adaptive-honeypot/defender/decision_engine/config/live.json /etc/adaptive-defender/live.json
sudo cp /opt/adaptive-honeypot/defender/decision_engine/systemd/adaptive-defender.service /etc/systemd/system/adaptive-defender.service
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now adaptive-defender
```

HTTP requests to `http://defender.lab/` return a permanent redirect to
`https://defender.lab/`. After Suricata writes an alert to
`/var/log/suricata/eve.json`, the decision engine writes the attacker source IP
to `/etc/nginx/maps/redirect_map.conf`, validates Nginx, reloads Nginx and
records the decision in `/var/log/adaptive-defender/decisions.jsonl`.
