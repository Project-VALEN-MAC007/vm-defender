#!/bin/sh
# Set up the TRAP real (production) server: the third machine, behind the
# Defender, that low-risk traffic reaches.
#
#   HTTP/HTTPS : Defender Nginx -> this server :8080 (real web)
#   SSH  22    : Defender nftables DNAT -> this server :22 (real sshd)
#   Telnet 23  : Defender nftables DNAT -> this server :23 (real telnetd)
#
# Risky sources are sent to the Honeypot (10.10.10.2) instead and never reach
# this server. The Defender does not rewrite the client address, so this
# server routes the outer network back through the Defender.
#
# Run as root on a fresh Ubuntu 24.04 VM attached to the internal network
# (VirtualBox "Project-Lab") plus a NAT adapter for management.
# Safe to run again.
set -eu

PROD_CIDR="${PROD_CIDR:-10.10.10.3/24}"
DEFENDER_INNER="${DEFENDER_INNER:-10.10.10.1}"
OUTER_NET="${OUTER_NET:-192.168.56.0/24}"
SITE_DIR="${SITE_DIR:-$(dirname "$0")/site}"
WEB_ROOT=/var/www/trap-real

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$SITE_DIR/index.html" ] || { echo "missing site files in $SITE_DIR" >&2; exit 1; }

echo "== internal interface"
if [ -z "${INNER_IF:-}" ]; then
  default_if="$(ip -o route show default | awk '{print $5; exit}')"
  candidates="$(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' \
                | grep -v -x -e lo -e "$default_if" || true)"
  if [ "$(printf '%s\n' "$candidates" | grep -c .)" -ne 1 ]; then
    echo "cannot pick the internal interface; set INNER_IF (ip -br link):" >&2
    ip -br link >&2; exit 1
  fi
  INNER_IF="$candidates"
fi
echo "internal interface: $INNER_IF ($PROD_CIDR, $OUTER_NET via $DEFENDER_INNER)"

cat > /etc/netplan/60-trap-inner.yaml <<NETPLAN
network:
  version: 2
  ethernets:
    $INNER_IF:
      dhcp4: false
      dhcp6: false
      addresses: [$PROD_CIDR]
      routes:
        - to: $OUTER_NET
          via: $DEFENDER_INNER
NETPLAN
chmod 600 /etc/netplan/60-trap-inner.yaml
netplan generate
netplan apply

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q nginx openssh-server inetutils-telnetd inetutils-inetd

echo "== real web on :8080"
install -d -m 0755 "$WEB_ROOT"
cp "$SITE_DIR"/*.html "$SITE_DIR"/*.css "$WEB_ROOT"/
cat > /etc/nginx/sites-available/trap-real <<'NGINX'
log_format trap_real escape=json
  '{"timestamp":"$time_iso8601","remote_addr":"$remote_addr",'
  '"client_ip":"$http_x_forwarded_for","method":"$request_method",'
  '"uri":"$request_uri","status":$status,"bytes":$body_bytes_sent,'
  '"user_agent":"$http_user_agent"}';

server {
    listen 8080 default_server;
    server_name _;
    root /var/www/trap-real;
    index index.html;
    access_log /var/log/nginx/trap-real.jsonl trap_real;
    location / { try_files $uri $uri/ =404; }
}
NGINX
ln -sf /etc/nginx/sites-available/trap-real /etc/nginx/sites-enabled/trap-real
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "== sshd and telnetd"
systemctl enable --now ssh
systemctl enable --now inetutils-inetd
if ! grep -q '^telnet' /etc/inetd.conf 2>/dev/null; then
  update-inetd --add 'telnet\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t/usr/sbin/telnetd'
fi
systemctl restart inetutils-inetd

echo "== checks"
ip -br addr show "$INNER_IF"
ip route get "$(echo "$OUTER_NET" | cut -d/ -f1 | sed 's/\.0$/.1/')"
ss -ltn | grep -E ':(8080|22|23) ' || true
curl -s -o /dev/null -w "local web: %{http_code}\n" http://127.0.0.1:8080/
echo "done"
