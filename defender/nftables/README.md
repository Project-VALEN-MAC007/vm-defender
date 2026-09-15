# D5 SSH/Telnet redirect safety gate

The template contains no guessed interface or Cowrie endpoint. Before apply:

- confirm outer/inner names with `ip -br link` and routes with `ip route`;
- receive Cowrie SSH IP/port, Telnet honeypot IP/port and return routes from person 2;
- capture `sudo nft list ruleset` to a root-only backup;
- render to a staging file and run `sudo nft -c -f STAGING_FILE`;
- keep the VirtualBox console open and arm the timed rollback in
  `docs/root-operations.md`;
- apply, then inspect `nft list ruleset`, `tcpdump` on both *observed* NICs and
  `conntrack -L` using only authorized lab traffic.

Rollback deletes only `table inet adaptive_defender`, then restores the exact
pre-change ruleset. Persistence is not enabled until runtime and restore tests
pass.

## Confirmed endpoint values

SSH/Cowrie honeypot endpoint received from the lab operator:

```text
__COWRIE_IP__=10.10.10.2
__COWRIE_PORT__=2222
```

Use `10.10.10.2` in nftables DNAT rules. The `/24` prefix belongs on the
honeypot interface configuration, not in the DNAT destination. Telnet is still
blocked from live rendering until `__TELNET_IP__`, `__TELNET_PORT__`,
`__OUTER_INTERFACE__` and `__INNER_INTERFACE__` are confirmed.

## SSH-only render

Use `generated/ssh-redirect.cowrie-2222.ssh-only.nft` when only the SSH/Cowrie
redirect is approved. It contains no Telnet rules, so the only remaining tokens
are `__OUTER_INTERFACE__` and `__INNER_INTERFACE__`.

Render those tokens from observed NIC names, then validate before applying:

```bash
cp defender/nftables/generated/ssh-redirect.cowrie-2222.ssh-only.nft /tmp/ssh-redirect.nft
$EDITOR /tmp/ssh-redirect.nft
sudo nft -c -f /tmp/ssh-redirect.nft
sudo nft -f /tmp/ssh-redirect.nft
sudo nft add element inet adaptive_defender ssh_redirect '{ 192.0.2.30 timeout 1800s }'
```

Replace `192.0.2.30` with the authorized source IP that should be redirected.
