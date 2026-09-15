# VM-Defender VirtualBox NIC checklist

Observed 2026-08-05 06:44 UTC: the guest has one Ethernet controller only,
`enp0s3` / MAC `08:00:27:97:ed:10`, attached to NAT with address
`10.0.2.15/24` and default gateway `10.0.2.2`. Keep this adapter unchanged as
the management/install path.

The following hardware change must be made in VirtualBox Manager while this VM
is powered off. It cannot be performed safely from inside the guest.

1. Keep Adapter 1 as NAT with cable connected.
2. Add Adapter 2 as **Internal Network**, cable connected. Use the same network
   name as VM-Attacker's lab adapter; proposed coordinated name:
   `adaptive-outer`. Do not use Bridged Adapter.
3. Add Adapter 3 as **Internal Network**, cable connected. Use the same network
   name as VM-Honeypot's lab adapter; proposed coordinated name:
   `adaptive-inner`. Do not use Bridged Adapter.
4. Start Defender and run `ip -details -brief link`. Do not assume the new
   interfaces will be named `enp0s8`/`enp0s9`.
5. Record both new names and MAC addresses. Confirm neither owns the default
   route.
6. Only then assign `192.168.56.10/24` to the observed outer interface and
   `10.10.10.1/24` to the observed inner interface. Neither lab connection gets
   a gateway or DNS server.
7. Confirm Adapter 1 still owns the sole default route before and after apply.

Peer requirements:

- VM-Attacker: `192.168.56.20/24` on `adaptive-outer` only.
- VM-Honeypot: `10.10.10.2/24` on `adaptive-inner` only.
- Both peers must have no Bridged connection during the experiment.

After the adapters exist, back up NetworkManager/Netplan, arm the timed
rollback from `docs/root-operations.md`, create separate NetworkManager
profiles for the two observed interface names, and run positive/negative
isolation tests before enabling IP forwarding.
