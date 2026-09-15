# Person 1 progress — VM-Defender

Last updated: 2026-08-05 06:44 UTC

## D1 re-inspection — 2026-08-05

- Date/time: 2026-08-05 06:44 UTC
- Status: **BLOCKED**
- Work actually performed: repeated read-only inspection of identity/sudo,
  login session, PCI Ethernet devices, kernel interfaces, addresses, all
  routes, NetworkManager profiles, Netplan, forwarding, services, listening
  ports and neighbor table.
- Commands: `id`, `sudo -n true`, `loginctl list-sessions`, `ip -details -brief
  link`, `ip -brief address`, `ip route show table all`, `nmcli connection
  show`, `nmcli device show`, `lspci -nnk`, `find /sys/class/net`, Netplan read,
  `systemctl is-active`, `sysctl net.ipv4.ip_forward`, `ss -lntup`, `ip neigh`.
- Actual result: exactly one PCI Ethernet controller exists (`00:03.0`, Intel
  82540EM/e1000), exposed as `enp0s3`, MAC `08:00:27:97:ed:10`. It owns
  `10.0.2.15/24` and the only IPv4 default route via `10.0.2.2`. Only the NAT
  gateway appears in the neighbor table. No outer/inner lab NIC exists.
- Target result: distinct lab-only interfaces holding Defender outer
  `192.168.56.10/24` and Defender inner `10.10.10.1/24`, with no default route
  or DNS on either.
- Network/firewall changes: none. The target addresses were not applied to the
  management NIC.
- sudo: non-interactive check exit 1 (`a password is required`). Protected
  firewall/config backup and apply remain unavailable.
- Services: NetworkManager active, Suricata active, Nginx inactive/absent;
  conntrack absent; IPv4 forwarding remains 0; no ports 22/80/443 listen.
- Positive test: management interface/default route present — passed.
- Negative isolation test: **NOT_RUN**, because the lab networks do not exist.
- Recovery test: **NOT_RUN**, because no network/firewall state was changed.
- Files created: `defender/network/virtualbox-nic-checklist.md`.
- Evidence: command results summarized in this entry; no PCAP/screenshot was
  created because no peer traffic was generated.
- Required external action: power off the VM and add two Internal Network
  adapters in VirtualBox Manager, matching the Attacker/Honeypot network names.
  After reboot, re-inspect actual interface names before configuring addresses.

Statuses are evidence-based.  `PASSED` is never used for an unexecuted test.

## Baseline inspection

- Date/time: 2026-08-04 19:32–19:35 UTC
- Status: **PASSED** (read-only inspection only)
- Work actually performed: inspected identity/sudo, OS/kernel/resources,
  hostname/time, interfaces/IP/MAC/routes/DNS, forwarding, services/packages,
  listening ports, repository locations, manuals and current configs.
- Actual host: user `yakult` (groups include `sudo`), but `sudo -n true` reports
  `a password is required`; Ubuntu 24.04.4 LTS; kernel 7.0.0-28-generic; 4 CPU;
  10 GiB RAM; root disk 39 GiB with 28 GiB free; hostname `ubuntu-vm`;
  timezone UTC with NTP active.
- Actual network: only `lo` and `enp0s3`; MAC `08:00:27:97:ed:10`;
  `enp0s3=10.0.2.15/24`; default gateway `10.0.2.2`; DNS observed through
  systemd-resolved; IPv4/IPv6 forwarding both 0.
- Management path: local Wayland session on `seat0/tty2`, `Remote=no`; SSH
  service is absent/inactive and no TCP port 22 is listening.
- Packages: Python 3.12.3, Suricata 7.0.3 and nftables 1.0.9 installed; Git,
  Nginx and conntrack absent.
- Ports: local DNS 53, CUPS 631 and application-local 45507; mDNS UDP 5353.
- Repository: no `.git` repository found under `/home/yakult`; existing
  `/home/yakult/Documents/Default Project` was empty and is used as project
  root. Git status cannot run because Git is absent.
- Existing README/AGENTS: none in the project. No Adaptive Honeypot PDF was
  found under the user home, `/media`, or `/mnt`; therefore the supplied scope
  and both Google Docs were used. Google Docs text export succeeded.
- Firewall inspection: `nft list ruleset`, `iptables-save`, and `ufw status`
  require root; actual ruleset remains unknown and is not claimed clean.
- Commands and exit codes: baseline system command `0`; network inspection
  aggregate `0` (individual root-only firewall commands failed as recorded);
  package/repository inspection `0`; Google Docs export `0`; initial
  unprivileged `suricata -T` failed because `/var/log/suricata` is not writable,
  not because a YAML parse error was proven.
- Evidence: this file and `backups/baseline-20260804T1932Z/`.
- Pending: privileged firewall dump and protected cloud-init netplan content.

## D1 — VM-Defender and network

- Date/time: 2026-08-04 19:35 UTC
- Status: **BLOCKED**
- Work actually performed: identified the only real interface, route and
  management channel; documented observed/target topology; prepared backup,
  timed rollback and console recovery procedure; kept forwarding disabled.
- Files created: `defender/network/topology.md`,
  `defender/network/adaptive-defender.nft.example`, `docs/root-operations.md`.
- Backups: exact readable baseline copies in
  `backups/baseline-20260804T1932Z/`; SHA-256 recorded by command output.
- Expected: separate lab-only outer and inner NICs; Defender reaches both lab
  VMs; Attacker cannot directly reach Honeypot; forward policy drop.
- Actual: the two lab NICs are missing. Target IPs were not applied to the NAT
  management NIC. No external VM was pinged or scanned because its IP was not
  observed on an authorized interface.
- Positive test: **NOT_RUN** — no Attacker/Honeypot interfaces or peers.
- Negative test: **NOT_RUN** — no isolated inner network exists.
- Recovery/rollback test: procedure written but **NOT_RUN**, because no network
  change was made and running it needs sudo.
- Problems pending: VM owner must attach two *isolated* VirtualBox adapters;
  sudo password is required for protected backup/firewall inspection/apply.
- Need from person 2: observed Honeypot interface/IP, Cowrie port/log path,
  WordPress/phpMyAdmin ports and health endpoints, plus return route.

## D2 — Suricata

- Date/time: 2026-08-04 19:35 UTC
- Status: **IN_PROGRESS** (host configuration is blocked by D1/sudo)
- Work actually performed: verified installed/enabled/running Suricata 7.0.3;
  captured its current config; created project-owned local rules.
- Files created: `defender/suricata/rules/local.rules`.
- Backups: `backups/baseline-20260804T1932Z/suricata.yaml` and
  `classification.config`.
- Commands/results: `suricata -T -l evidence/test-results -c
  /etc/suricata/suricata.yaml -S defender/suricata/rules/local.rules` exit 0;
  active host service exit 0; `/var/log/suricata/eve.json` exists (11,820,615
  bytes at inspection). Existing HOME_NET is RFC1918 ranges and EXTERNAL_NET is
  `!$HOME_NET`; host config has eve-log types section.
- Positive test: offline 4-packet HTTP PCAP produced alerts SID 2200001 and
  2200003 with timestamp `2026-08-04T19:46:23+0000`, source
  `198.51.100.20`, protocol TCP and severity 1; replay exit 0.
- Negative test: offline benign `/health` + `curl/8.0` PCAP produced no alert;
  replay exit 0.
- Recovery/rollback: host activation not performed, so restore was not applied;
  exact current config backup exists and user-space staged rollback is tested in
  D8.
- Evidence: `evidence/baseline/http-positive.pcap`,
  `evidence/baseline/http-benign.pcap`,
  `evidence/test-results/http-positive-run1/eve.json`,
  `evidence/test-results/http-benign-run1/eve.json`.
- Pending: actual outer/inner/loopback capture test, safe restart/reboot test and
  host local.rules activation require D1 and sudo.
- Need from person 2: normalized alert/correlation sample schema.

## D3 — Detection rules

- Date/time: 2026-08-04 19:35 UTC
- Status: **IN_PROGRESS**
- Work actually performed: authored HTTP path/UA, TLS metadata, SSH
  version/burst and scan-history rules in SID range 2200001–2200999; documented
  positive and benign cases.
- Actual: HTTP path and User-Agent positive/benign tests passed offline. TLS,
  SSH burst/version and scan thresholds passed syntax only; their actual alerts
  remain **NOT_RUN**, so D3 is not marked passed.
- Files: `defender/suricata/rules/local.rules`,
  `defender/suricata/rule-tests.md`.
- Need from person 2: SID/severity mapping confirmation and sample artifacts.

## D4 — Nginx redirect

- Date/time: 2026-08-04 19:41–19:52 UTC
- Status: **BLOCKED**
- Work: created HTTP/HTTPS reverse-proxy/TLS template, real backend target
  `127.0.0.1:8080`, source-IP headers/log schema, profiles real/wordpress/
  phpmyadmin, managed 503 response and atomic map adapter.
- Files: `defender/nginx/adaptive-honeypot.conf.template`, `redirect_map.conf.example`,
  `README.md`, Decision Engine `adapters.py`.
- Positive test: atomic map render test passed; Decision Engine dry-run selected
  wordpress for HTTP risk 40. Dashboard showed this decision.
- Negative test: non-IP map key rejected; non-loopback dashboard bind rejected.
- Recovery test: validator failure restored the exact previous map; unit test
  passed.
- Expected vs actual: Nginx `-t`, HTTP/HTTPS routing and backend-down live test
  are **NOT_RUN** because Nginx is absent and backend/certificate values are
  unverified. No template token was rendered or applied.
- Need from person 2: actual WordPress/phpMyAdmin IP:port, health paths and
  expected responses.

## D5 — SSH redirect

- Date/time: 2026-08-04 19:41–19:52 UTC
- Status: **BLOCKED**
- Work: created policy-drop/DNAT/masquerade template with timed
  `ssh_redirect`/`temporary_block` sets and validated dry-run command adapter.
- Files: `defender/nftables/ssh-redirect.nft.template`, `README.md`,
  Decision Engine `adapters.py`.
- Positive test: risk 45 selected `redirect_ssh/cowrie`; generated bounded nft
  add-element command in dry-run; unit test passed.
- Negative test: invalid IP/set/timeout validation exists; no live packet was
  redirected.
- Recovery/persistence: **NOT_RUN**; this is intentional because inner/outer
  NICs, Cowrie endpoint, conntrack and privileged pre-change ruleset are absent.
- Need from person 2: Cowrie actual IP/port, health/log path and return route.

## D6 — Decision Engine

- Date/time: 2026-08-04 19:38–19:52 UTC
- Status: **IN_PROGRESS** (implementation tests pass; host service not installed)
- Work: implemented EVE reader, atomic inode/offset checkpoint, rotation,
  normalization, SHA-256 dedup, risk/threshold mapping, scan+SSH cross-protocol
  history, decay/expiry, five actions, atomic Nginx adapter, nft set adapter,
  three-attempt retry, error audit, dry-run, config validation and hardened
  systemd unit.
- Files: `defender/decision_engine/` and `tests/test_decision_engine.py`.
- Commands/results: `python3 -m unittest discover -s tests -v` — 11/11 passed,
  exit 0. CLI dry-run exit 0 produced web and SSH decisions with reason, risk,
  profile, start and expiry.
- Positive tests: event normalization/action, checkpoint restart, rotation,
  scan→next HTTP risk and decay passed.
- Negative tests: duplicate ignored; bad dashboard/config address rejected;
  invalid map IP rejected.
- Recovery test: failed Nginx validation restored prior map; failed deploy
  health restored exact prior rules.
- Evidence: `evidence/test-results/decisions.jsonl` and test output recorded here.
- Pending: install user/config/unit under root, live EVE permissions and real
  Nginx/nft adapter integration.

## D7 — Dashboard and baseline

- Date/time: 2026-08-04 19:47–19:52 UTC
- Status: **IN_PROGRESS**
- Work: loopback-only dashboard shows decisions and service/backend status,
  summaries, JSON and CSV exports; metric module covers accuracy, FPR and
  decision/redirect latency.
- Positive test: temporary `127.0.0.1:19090` server returned summary (2
  decisions), CSV and status endpoints; each curl exit 0. Server was then
  stopped intentionally with Ctrl-C (exit 1 due KeyboardInterrupt).
- Negative test: `0.0.0.0` bind config is rejected; empty/malformed log handling
  is safe.
- Baseline dataset: benign, known HTTP, known SSH/scan, negative/false-positive,
  and latency fields exist in `tests/fixtures/baseline.json`; calculated
  accuracy 1.0 and FPR 0.0 for this synthetic 4-row sample only.
- Resource measurement: test suite elapsed 0.14 s, max RSS 23,932 KiB, exit 0;
  host baseline is 4 CPU, 10 GiB RAM, root disk 24% used; Suricata observed
  near 600 MiB during initial service inspection.
- Pending: authorized live-traffic baseline, redirect latency, backend health
  values, dashboard screenshot and longer CPU/RAM/disk sampling.

## D8 — Validation/deploy/cross-protocol

- Date/time: 2026-08-04 19:42–19:50 UTC
- Status: **IN_PROGRESS** (user-space pipeline passed; host deploy not run)
- Work: implemented candidate schema/state registry, syntax, duplicate/overlap,
  baseline regression, malicious replay and performance/FPR gates; staged
  backup/activate/reload/health/rollback; cross-protocol history and expiry.
- Positive end-to-end test: redacted honeypot evidence → candidate SID 2200401
  → five gates approved → Suricata syntax test → temporary staged deploy → next
  offline `/lab-repeat` attack detected SID 2200401. Exit 0, one alert,
  `detected_next_attack=true`; host service was explicitly not reloaded.
- Negative tests: duplicate SID rejected; failed health check changed state to
  `rolled_back` and restored exact `original\n` rules; both unit tests passed.
- Performance gate: 0.226 ms/event in the recorded feedback-loop run; synthetic
  FPR 0.0.
- Evidence: `evidence/test-results/feedback-loop-report.json`,
  `evidence/baseline/http-feedback.pcap`, candidate/baseline fixtures.
- Pending: real candidate/metadata/PCAP/quality report from person 2, reviewer
  approval and safe host activation/monitoring under sudo.
