# TRAP Round 9 — Isolation deployment and verification

Test start UTC: 2026-10-10T20:24:17.274908+00:00 (11 October 2026, 03:24:17 Asia/Bangkok). Run ID: round9-20261010T202417Z. Traffic and decisions in this report are filtered at or after test-start. Before snapshots are labeled separately. No implementation changes or commits were made.

**Result:** D1, D2 required isolation checks, D3, D5, D6, D7 and D0 regression passed. All 12 round-8 FAIL isolation pairs now time out with a positive matching counter measured separately per pair. D4 data paths and log sync passed; its deploy-agent subcheck is NOT_TESTABLE. D8 Clone is NOT_TESTABLE because this lab has neither SNARE nor the deploy agent. This is not a claim that every feature of the whole product passed.

## Deployment and evidence boundaries

The prior four report/Matrix/ZIP/SHA files were moved to Previous-Reports/round8-before-round9-20261010T202417Z and destination SHA verified: [host/archive.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/archive.json). Existing round-8 evidence remains in place, including failures.

Before docker ps, listeners, routes, Docker networks and complete nft/iptables snapshots are retained per VM in host/*-network-inspect-before.json. Defender has no Docker executable; that diagnostic is N/A and does not invalidate its successful nft backup. All three nonempty backups are at /root/trap-backup/nftables.before-isolation.nft; hashes and file verification are retained in host/*-firewall-backup.json and host/*-D1-final.json.

The complete working tree, including untracked files, was synchronized to /opt/trap on all three VMs; .git, local caches and .env were excluded to preserve deployed private environment settings. Each VM verified 701 manifest entries with mismatch=[]. See [host/sync-manifest.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/sync-manifest.json) and host/*-source-delivery-verified.json. The source audit checked 361 implementation/document files and found no changed or missing files: [source-unchanged-audit.json](TRAP-Retest-Evidence/round9-20261010T202417Z/source-unchanged-audit.json). Report copies are the only repository outputs added by this test.

Installed role files and service in order Web → Honeypot → Defender. Each nft --check passed. Before each apply, a three-minute systemd rollback timer was armed to disable trap-isolation.service and delete only inet trap_isolation. This adapts the documented rollback to avoid restoring/flushing unrelated Docker or adaptive_defender tables. A new management SSH session and role services were verified before cancelling that timer. No rollback fired and management survived every apply. /etc/trap directory permissions were preserved. See host/*-rollback-armed.json, *-isolation-applied.json, *-new-SSH-management-verified.json and *-rollback-cancelled.json.

Honeypot compose recreated Cowrie with read_only=true and /tmp tmpfs. Defender runtime /etc/trap/trap.json now has web_deploy.allowed_targets=[10.10.10.3:8080], backed up privately at /root/trap-backup/trap.before-round9.json. No deploy-agent config existed to remove obsolete fields from. [host/defender-allowed-targets-config.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/defender-allowed-targets-config.json)

| VM | Unit tests | Duration | Result |
|---|---:|---:|---|
| defender | 157/157 | 109.135s | PASS |
| honeypot | 157/157 | 154.349s | PASS |
| web | 157/157 | 111.938s | PASS |

Full original logs, including test_isolation and test_deploy_agent, are retained in host/*-unit-full-log-final.json. An earlier collector snapshot of Honey tests was incomplete and the early Web snapshot found no file; those diagnostics are retained, while final full logs establish the completed results. Tests were not rerun merely to obtain a clean claim.

Baseline host free RAM: 3068.4 MiB. VM RAM/time/NTP snapshots: [host/baseline.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/baseline.json). Fresh attacker IPs: 192.168.56.12–22, one per case; allocator checked historical Defender logs and Honey origin logs. [fresh-source-IP-audit.json](TRAP-Retest-Evidence/round9-20261010T202417Z/fresh-source-IP-audit.json) has no earlier matches. D2 deliberately uses the same fixed VM/container origins and exact destination catalog as round 8. Attacker requests target only 192.168.56.10; the explicitly requested D2 Internet test is a TCP connect-only probe to 1.1.1.1:443 from Honey origins.

## D1–D2 isolation

All three services are enabled and active with inet trap_isolation present; Cowrie ReadonlyRootfs=true. The exact 22-target catalog was repeated for Honey host, Cowrie and web-honeypot (66 required pairs), plus web-app (22 additional observations), and all 22 targets for each of three containers after reboot (66 pairs). The CSV contains every individual result, UTC interval, prior-round classification and evidence path.

| Phase | Origin | Matching counter | Packet delta across catalog batch |
|---|---|---|---:|
| pre-reboot | Honeypot-VM | honeypot host -> lab | 55 |
| pre-reboot | cowrie | container egress | 58 |
| pre-reboot | web-honeypot | container egress | 58 |
| pre-reboot | web-app | container egress | 0 |
| post-reboot- | cowrie | container egress | 60 |
| post-reboot- | web-honeypot | container egress | 61 |
| post-reboot- | web-app | container egress | 0 |

Batch counters are aggregate and do not attribute each UDP datagram. For the 12 prior FAIL pairs, separate before/after counters were then measured for each single TCP connection:

| Origin | Destination | Round 8 | Round 9 | Matching drop delta |
|---|---|---|---|---:|
| Honeypot-VM | 10.10.10.3:8080 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 4 |
| Honeypot-VM | 10.10.10.3:23 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| Honeypot-VM | 10.10.10.3:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| Honeypot-VM | 10.10.10.1:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| cowrie | 10.10.10.3:8080 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| cowrie | 10.10.10.3:23 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| cowrie | 10.10.10.3:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| cowrie | 10.10.10.1:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| web-honeypot | 10.10.10.3:8080 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| web-honeypot | 10.10.10.3:23 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 4 |
| web-honeypot | 10.10.10.3:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |
| web-honeypot | 10.10.10.1:22 | FAIL isolation / CONNECTED | TimeoutError (~3s) | 3 |

[host/D2-old-FAIL-per-pair-results.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D2-old-FAIL-per-pair-results.json)

| Phase | Origin → 1.1.1.1:443 | Actual |
|---|---|---|
| pre-reboot | Honeypot-VM | CONNECTED  |
| pre-reboot | cowrie | NOT_CONNECTED TimeoutError |
| pre-reboot | web-honeypot | NOT_CONNECTED TimeoutError |
| pre-reboot | web-app | NOT_CONNECTED OSError |
| post-reboot- | cowrie | NOT_CONNECTED TimeoutError |
| post-reboot- | web-honeypot | NOT_CONNECTED TimeoutError |
| post-reboot- | web-app | NOT_CONNECTED OSError |

Honey host Internet remains reachable through NAT management, as requested. All Cowrie/web-honeypot TCP destinations time out with increased container-egress counters. Honey host UDP sendto returns local EPERM while its OUTPUT drop counter rises; it is recorded as an observation, not a TCP timeout. Cowrie/web-honeypot UDP probes show no response and remain NOT_PROVEN per individual UDP row, rather than assuming silence proves filtering. Additional web-app probes return ENETUNREACH: its Docker network is internal, so no route exits and nft counters need not increase. No route or firewall was changed to manufacture counter proof. All 12 formerly reachable TCP pairs satisfy the precise timeout-plus-counter requirement.

## D3, D4 and D5 functional paths

D3 used source 192.168.56.15, a real redirect_ssh decision and an authenticated Cowrie PTY. Both wget http://10.10.10.3:8080/ and curl http://10.10.10.1:9090/ appear in Cowrie command input. Cowrie logs explicitly say “Attempt to access blocked network address”; its client responses are retained in [defender/D3/cases.json](TRAP-Retest-Evidence/round9-20261010T202417Z/defender/D3/cases.json). Web and Defender captures overlap the command interval and both show 0 packets captured, 0 kernel drops and a 24-byte pcap header. [host/D3-capture-statistics.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D3-capture-statistics.json). Cowrie command emulation alone cannot prove nft filtering; D2 uses native container sockets and matching counters for that proof. Capture text and relevant service logs remain in host/D3-*-capture-and-service-log.json; private pcap files remain on the VMs.

D4 SSH DNAT is evidenced by the D3 Cowrie source-IP session and redirect_ssh decision. Telnet source 192.168.56.20 accumulated a LibSSH trigger followed by a real failed Telnet login; decision redirect_telnet and a new Cowrie telnet origin session were confirmed. HTTP/HTTPS redirect logs show upstream 10.10.10.2:8084; web-honeypot forwards to internal web-app with HTTP 200 before and after reboot. trap-log-sync.timer remained active and the sessions reached Dashboard API and User UI. [defender/Routes/cases.json](TRAP-Retest-Evidence/round9-20261010T202417Z/defender/Routes/cases.json), [host/D4-forward-internal.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D4-forward-internal.json), [Defender-service-and-deploy-evidence.json](TRAP-Retest-Evidence/round9-20261010T202417Z/Defender-service-and-deploy-evidence.json)

The requested agent /v1/status probe returned curl exit 7. The unit is inactive, config absent and no port 8091 listener or SNARE container exists: [host/D4-agent-status.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D4-agent-status.json), [host/D8-installation-presence.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D8-installation-presence.json). D4 is therefore partial at the feature level; the agent subitem and D8 Clone/preview/Deploy are NOT_TESTABLE under the prompt’s conditional installation rule. No mock status or fabricated Clone result is used.

| D5 case | Fresh source | Actual | Result |
|---|---|---|---|
| D5-low-risk-real-SSH | 192.168.56.17 | Authenticated session: hostname project-web, user kali; no redirect decision | PASS |
| D5-low-risk-real-Telnet | 192.168.56.18 | Authenticated session: hostname project-web, user kali; no redirect decision | PASS |
| D5-low-risk-real-HTTP | 192.168.56.19 | HTTP 200; Nginx upstream 10.10.10.3:8080 | PASS |

Real SSH and Telnet responses and Web ssh/inetd journal are retained. [Web-origin.json](TRAP-Retest-Evidence/round9-20261010T202417Z/Web-origin.json). The real web application suppresses access logging, so the Nginx upstream log and HTTP response are used without inventing a Web access-log entry.

## D6–D7 read-only operation and reboot

Cowrie logs after recreation, after D3 and after reboot contain no Read-only file system error. SSH/Telnet startup readiness and command/session logs prove normal operation; read_only is still true. Existing No moduli warnings are retained and do not concern file writes. [host/honeypot-compose-readonly.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/honeypot-compose-readonly.json), [host/D6-after-D3.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D6-after-D3.json), [host/D6-post-reboot.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D6-post-reboot.json)

Honeypot was rebooted once. boot_id changed; the systemd monotonic timestamps show trap-isolation active at 6.400578s, before Docker process start at 16.160531s and Docker active at 20.848528s. Boot journal separately records isolation completion before Docker start. Cowrie, web-honeypot and web-app restarted automatically and ports 2222/2223/8084 listen. [host/D7-after-reboot.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D7-after-reboot.json)

Management SSH was temporarily unavailable during reboot, then recovered at 20:44:52 UTC (~45s after dispatch). Every failed banner poll remains in [host/D7-recovery-polls.json](TRAP-Retest-Evidence/round9-20261010T202417Z/host/D7-recovery-polls.json). No firewall edits, rollback or second reboot were performed. An auxiliary VirtualBox guest-control read was unavailable; the console had reached the login prompt (screenshots/D7-console.png). The observed outage was bounded by the reboot and recovery records; no speculative root cause is assigned.

After reboot, Cowrie and web-honeypot still time out for every catalog TCP destination with increased drop counters; web-app still has no outside route. Fresh-source postboot redirect SSH and HTTP both pass with origin logs: [defender/PostReboot/cases.json](TRAP-Retest-Evidence/round9-20261010T202417Z/defender/PostReboot/cases.json).

## D0 regression

| Case | Source | Actual | Result |
|---|---|---|---|
| D0-B3-B4-A3-HTTP-and-D4-redirect | 192.168.56.12 | Same header set/order excluding Date; no anonymous PHPSESSID; robots 200 with identical body SHA; generic sessions found | PASS |
| D0-B3-B4-A3-HTTPS-redirect | 192.168.56.13 | Same header set/order excluding Date; no anonymous PHPSESSID; robots 200 with identical body SHA; generic sessions found | PASS |
| D0-B7-existing-alsid-portal | 192.168.56.14 | Original alsid accepted by decoy portal; HTTP 200 Customer portal; fake data retained | PASS |
| D0-Rabbit-Hole-trail-and-D4-HTTP | 192.168.56.16 | /backup/ → config.json → API all HTTP 200 with node_id in origin logs | PASS |

All raw before/after responses, header order, body hashes, decision timestamps, Nginx profile/upstream, and Honey origin events are in [defender/Regression/cases.json](TRAP-Retest-Evidence/round9-20261010T202417Z/defender/Regression/cases.json). The source .13 HTTPS session is visible to trapuser with source/keyword/Honeypot/HTTPS filters: one session, four actions, 0.1s dwell. [screenshots/A3-HTTPS-session.txt](TRAP-Retest-Evidence/round9-20261010T202417Z/screenshots/A3-HTTPS-session.txt)

![](TRAP-Retest-Evidence/round9-20261010T202417Z/screenshots/A3-HTTPS-session.png)

## Deliverables and remaining limits

TRAP-Test-Matrix.csv contains 207 completed rows, including all catalog pairs. ZIP: round9-20261010T202417Z-evidence.zip; adjacent SHA256 file and internal manifest.json verify integrity. The bundle contains filtered raw Defender and both Honey origin logs, commands/results, before/after firewall and boot evidence, response bodies and screenshots. Passwords, TOTP secrets, cookie values and private/.env files are excluded or redacted; CRC, secret scan, manifest hashes and copied report hashes are verified during packaging.

No new implementation FAIL was observed in the requested executable checks. Remaining limits: SNARE/deploy-agent tests unavailable; UDP silence is not per-datagram proof; web-app denial is internal-network routing rather than nft counter evidence. The new firewall covers this catalog and boot sequence; this report does not claim untested alternate networks or bypasses are impossible. No round 1–8 feature suite was repeated beyond the regression expressly requested here.
