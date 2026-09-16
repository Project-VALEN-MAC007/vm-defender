from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Callable, List


Runner = Callable[[List[str]], subprocess.CompletedProcess]


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _service_status(name: str, runner: Runner) -> str:
    result = runner(["systemctl", "is-active", name])
    return (result.stdout or result.stderr).strip() or f"exit={result.returncode}"


def _has_address(output: str, address_prefix: str) -> bool:
    return address_prefix in output


def _has_management_nat(output: str) -> bool:
    return any(part.startswith("10.0.") for part in output.split())


def assess(runner: Runner = _run, which: Callable[[str], str | None] = shutil.which) -> dict:
    checks: list[Check] = []
    ip_result = runner(["ip", "-brief", "address"])
    addresses = ip_result.stdout
    has_outer = _has_address(addresses, "192.168.56.10/")
    has_inner = _has_address(addresses, "10.10.10.1/")
    has_management = _has_management_nat(addresses)
    nat_only = has_management and not (has_outer and has_inner)
    checks.append(Check(
        "lab_outer_interface",
        "passed" if has_outer else "blocked",
        "Defender outer address 192.168.56.10 is present" if has_outer
        else "missing Defender outer address 192.168.56.10 on a lab-only NIC",
    ))
    checks.append(Check(
        "lab_inner_interface",
        "passed" if has_inner else "blocked",
        "Defender inner address 10.10.10.1 is present" if has_inner
        else "missing Defender inner address 10.10.10.1 on a lab-only NIC",
    ))
    checks.append(Check(
        "management_nic_preserved",
        "passed" if has_management else "warning",
        "management NAT address is still present" if has_management
        else "expected management NAT address in 10.0.0.0/8 was not observed",
    ))
    if nat_only:
        checks.append(Check(
            "deployment_gate",
            "blocked",
            "only management/NAT networking is observed; do not apply lab addresses to enp0s3",
        ))

    for binary in ("suricata", "nft", "nginx", "conntrack"):
        installed = which(binary) is not None
        checks.append(Check(
            f"binary_{binary}",
            "passed" if installed else "blocked",
            f"{binary} is installed" if installed else f"{binary} is not installed",
        ))

    for service in ("suricata", "nginx"):
        status = _service_status(service, runner)
        checks.append(Check(
            f"service_{service}",
            "passed" if status == "active" else "blocked",
            f"{service} service is {status}",
        ))

    return {
        "ready_for_live_deploy": all(check.status == "passed" for check in checks),
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only VM-Defender live deployment readiness check")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    args = parser.parse_args()
    report = assess()
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if report["ready_for_live_deploy"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
