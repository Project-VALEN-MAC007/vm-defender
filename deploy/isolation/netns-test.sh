#!/bin/bash
# Offline check of honeypot.nft / web.nft / defender.nft in throw-away network
# namespaces (no root, touches nothing on the machine):
#
#   unshare -rn --kill-child bash deploy/isolation/netns-test.sh deploy/isolation
#
# The namespace that runs this script plays the Honeypot host (10.10.10.2) with a
# Docker-like bridge br-cowrie (container 172.18.0.2, DNAT 2222, masquerade);
# child namespaces play the Defender (10.10.10.1, 192.168.56.10) and Web (10.10.10.3).
# Every line must start with "ok". It does not replace the round-9 test on the VMs.
set -u
ISO=$(cd "$1" && pwd)
spawn() { unshare -n sleep 120 >/dev/null 2>&1 & echo $!; }
DEF=$(spawn); WEB=$(spawn); C=$(spawn); sleep 0.3
inns() { nsenter -t $1 -n "${@:2}"; }
ip link set lo up
ip link add lab0 type bridge; ip link set lab0 up; ip addr add 10.10.10.2/24 dev lab0
for p in DEF WEB; do pid=${!p}
  ip link add v$p type veth peer name e$p; ip link set v$p master lab0 up; ip link set e$p netns $pid
done
inns $DEF ip link set lo up; inns $DEF ip link set eDEF name eth0; inns $DEF ip addr add 10.10.10.1/24 dev eth0; inns $DEF ip link set eth0 up
inns $DEF ip addr add 192.168.56.10/24 dev lo
inns $WEB ip link set lo up; inns $WEB ip link set eWEB name eth0; inns $WEB ip addr add 10.10.10.3/24 dev eth0; inns $WEB ip link set eth0 up
ip route add 192.168.56.0/24 via 10.10.10.1
# docker-like container bridge
ip link add br-cowrie type bridge; ip addr add 172.18.0.1/16 dev br-cowrie; ip link set br-cowrie up
ip link add vC type veth peer name eC; ip link set vC master br-cowrie up; ip link set eC netns $C
inns $C ip link set lo up; inns $C ip link set eC name eth0; inns $C ip addr add 172.18.0.2/16 dev eth0; inns $C ip link set eth0 up; inns $C ip route add default via 172.18.0.1
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -qw net.ipv4.ip_forward=1 || echo "ip_forward not writable"
# docker-like nat (separate table, like Docker's)
nft -f - <<'N'
table ip dockerlike {
  chain pre { type nat hook prerouting priority dstnat; ip daddr 10.10.10.2 tcp dport 2222 dnat to 172.18.0.2:2222; }
  chain post { type nat hook postrouting priority srcnat; ip saddr 172.18.0.0/16 oifname != "br-cowrie" masquerade; }
}
N
srv() { inns $1 python3 -c "
import socket,sys,threading
for p in sys.argv[1:]:
  s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',int(p)));s.listen(8)
  threading.Thread(target=lambda s=s:[s.accept()[0].close() for _ in iter(int,1)],daemon=True).start()
import time;time.sleep(120)" "${@:2}" >/dev/null 2>&1 & }
srv $DEF 22 9090 80; srv $WEB 8080 22 23; srv $C 2222; srv $$ 22 8091
sleep 0.8
probe() { # name pid ip port expect
  if [ "$2" = self ]; then r=$(python3 -c "import socket,sys;s=socket.socket();s.settimeout(1.5)
try: s.connect((sys.argv[1],int(sys.argv[2])));print('CONNECTED')
except Exception as e: print('BLOCKED')" $3 $4)
  else r=$(inns $2 python3 -c "import socket,sys;s=socket.socket();s.settimeout(1.5)
try: s.connect((sys.argv[1],int(sys.argv[2])));print('CONNECTED')
except Exception as e: print('BLOCKED')" $3 $4); fi
  ok=FAIL; [ "$r" = "$5" ] && ok=ok; printf '%-4s %-34s %-10s expect %-10s\n' $ok "$1 -> $3:$4" $r $5; }
matrix() {
  probe "Honeypot host" self 10.10.10.3 8080 $1; probe "Honeypot host" self 10.10.10.3 22 $1
  probe "Honeypot host" self 10.10.10.1 22 $1; probe "Honeypot host" self 192.168.56.10 80 $1
  probe "container" $C 10.10.10.3 8080 $1; probe "container" $C 10.10.10.1 22 $1
  probe "container" $C 10.10.10.2 22 $1; probe "container" $C 172.18.0.1 8091 $1
  probe "Web" $WEB 10.10.10.2 22 $1; probe "Web" $WEB 10.10.10.2 2222 $1
  probe "Defender (allowed)" $DEF 10.10.10.2 22 CONNECTED; probe "Defender (allowed)" $DEF 10.10.10.2 8091 CONNECTED
  probe "Defender DNAT (allowed)" $DEF 10.10.10.2 2222 CONNECTED; probe "Defender proxy (allowed)" $DEF 10.10.10.3 8080 CONNECTED
}
echo "### before (no isolation)"; matrix CONNECTED
echo "### honeypot.nft on Honeypot only"; nft -f $ISO/honeypot.nft; matrix BLOCKED
echo "### web.nft + defender.nft only (Honeypot rules removed, e.g. attacker is root there)"
nft delete table inet trap_isolation; inns $WEB nft -f $ISO/web.nft; inns $DEF nft -f $ISO/defender.nft
probe "Honeypot host" self 10.10.10.3 8080 BLOCKED; probe "Honeypot host" self 10.10.10.3 22 BLOCKED
probe "Honeypot host" self 10.10.10.1 22 BLOCKED; probe "Honeypot host" self 192.168.56.10 80 BLOCKED
probe "container" $C 10.10.10.3 8080 BLOCKED; probe "container" $C 10.10.10.1 22 BLOCKED
probe "Defender proxy (allowed)" $DEF 10.10.10.3 8080 CONNECTED; probe "Defender (allowed)" $DEF 10.10.10.2 22 CONNECTED
echo "### counters (defender)"; inns $DEF nft list table inet trap_isolation | grep counter
kill $DEF $WEB $C 2>/dev/null; kill $(jobs -p) 2>/dev/null
