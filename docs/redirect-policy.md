# Redirect-only response policy

The engine supports `allow`, `monitor`, `redirect_web`, `redirect_ssh`, and
`redirect_telnet`. Configure exactly two risk thresholds:

```json
{"thresholds": {"monitor": 15, "redirect": 40}}
```

Values must satisfy `0 <= monitor < redirect <= 100`. Scores at or above the
redirect threshold continue to redirect, including the maximum score of 100.
HTTP uses the configured web profile; SSH and Telnet use Cowrie.

For an existing installation, back up the configuration and scoped nftables
table, stop the engine, replace the old thresholds with these two keys, deploy
the updated source and nftables template, validate the configuration, and
restart the engine and Dashboard. Use a timed rollback while applying firewall
changes. Old configuration keys are rejected to expose incomplete migrations.

IPv6 SSH/Telnet traffic is recorded as `monitor` with reason
`ipv6_shell_redirect_unsupported:monitor`, because the current adapter supports
IPv4 DNAT only. IPv6 HTTP can still use the Nginx map.

The firewall's network isolation and invalid-connection filtering remain in
place. Historical audit logs remain available; old actions in those logs do
not enable a current response feature. Dashboard destination summaries contain
only `real` and `honeypot`.

## Scan-only signatures

Network scans are detected and alerted only. Signatures listed in
`scan_only_signatures` (default `[2017616]`, ET SCAN NETWORK Masscan) are
capped at `monitor` at every threshold; the decision reason ends with
`scan_only_policy:monitor`. Their score still counts, so a later attack from
the same source is redirected sooner. SSH frequent connections (2001219) and
LibSSH brute force (2006546) are not scan-only: they redirect to Cowrie as
described in the thesis. Add SIDs to the list to make them alert-only.

## Thresholds edited in the Dashboard

`thresholds_path` (live: `/var/lib/trap/engine/thresholds.json`) holds the
thresholds the Dashboard saves. When the file exists it overrides
`thresholds` in the engine config, which stays read-only under
`/etc/adaptive-defender`. The engine reloads it every cycle without losing
risk state; an invalid file is ignored (journald: `threshold_reload_failed`)
and the last good thresholds stay in use. Install with
`deploy/install-dashboard-helpers.sh`.
