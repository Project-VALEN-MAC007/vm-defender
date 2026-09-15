# D1 topology and isolation gate

## Observed (2026-08-04 UTC)

```text
VirtualBox NAT 10.0.2.0/24
        |
 enp0s3 10.0.2.15/24  (management/NAT; must remain unchanged)
        |
   VM-Defender

outer lab NIC: MISSING
inner lab NIC: MISSING
```

## Target after the VM owner adds isolated adapters

```text
VM-Attacker 192.168.56.20/24
        |
 isolated outer network (no Internet bridge)
        |
Defender outer 192.168.56.10/24
Defender inner 10.10.10.1/24
        |
 isolated inner network (no Internet bridge)
        |
VM-Honeypot 10.10.10.2/24
```

Interface names remain unset until `ip -br link` shows the newly attached
adapters.  The D1 apply gate must reject `enp0s3`, a default-route interface,
or any interface whose network is not explicitly identified as lab-only.

Forwarding remains disabled until D5.  When enabled, the forward policy is
drop and only established replies plus explicit Defender-to-Honeypot DNAT
flows are accepted.  No general outer-to-inner routing is allowed.
