"""Network-layer helpers.

Split into two halves:

* :func:`parse_nmap` is pure — it turns nmap stdout into a host/port dict and is
  fully unit-tested. Pulling it out of the scan task is what makes the parsing
  regressions the original code hit ("scan finds no host because ``-F`` skipped
  5985", off-by-one on ``/tcp`` lines) testable without standing up a range.
* :func:`heal_dns` and :func:`clear_apt_locks` are side-effecting but take an
  injected ``runner`` callable (``(bash: str, timeout: int) -> str``) instead of
  reaching for VirtualBox directly, so they are decoupled from the transport and
  can be exercised with a fake runner.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Protocol

from .scope import Scope


class GuestRunner(Protocol):
    def __call__(self, bash: str, timeout: int = ...) -> str: ...


_REPORT_RE = re.compile(r"Nmap scan report for\s+(.+)")
_IPV4_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


def parse_nmap(output: str, scope: Scope) -> dict[str, dict]:
    """Parse ``nmap`` stdout into ``{ip: {"open_ports": [...], "os": str}}``.

    Only in-scope hosts are returned; port lines that follow an out-of-scope
    report header are dropped along with the header, so a deny-listed gateway
    can never leak a phantom open port into the state summary.
    """
    hosts: dict[str, dict] = {}
    current: str | None = None

    for line in output.splitlines():
        m = _REPORT_RE.match(line)
        if m:
            ip_match = _IPV4_RE.search(m.group(1).strip())
            current = None
            if ip_match and scope.is_target_allowed(ip_match.group(1)):
                current = ip_match.group(1)
                hosts.setdefault(current, {"open_ports": [], "os": "unknown"})
            continue

        if current and "/tcp" in line and "open" in line:
            token = line.split()[0] if line.split() else ""
            port_str = token.split("/")[0]
            if port_str.isdigit():
                port = int(port_str)
                if port not in hosts[current]["open_ports"]:
                    hosts[current]["open_ports"].append(port)

        if current and "Windows" in line:
            hosts[current]["os"] = "Windows"

    return hosts


def clear_apt_locks(runner: GuestRunner, timeout: int = 30) -> None:
    """Clear a stale dpkg/apt lock left by a previous timed-out install.

    ``VBoxManage guestcontrol`` does not propagate a host-side timeout kill into
    the guest, so a killed ``apt-get`` can keep holding the lock. Clearing it
    before every attempt lets retries self-heal instead of hanging forever.
    """
    runner(
        "sudo pkill -9 -f 'apt-get install' 2>/dev/null; "
        "sudo pkill -9 -f 'apt-get update' 2>/dev/null; "
        "sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock "
        "/var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null; "
        "sudo dpkg --configure -a 2>/dev/null; true",
        timeout=timeout,
    )


def heal_dns(
    runner: GuestRunner,
    attempts: int = 6,
    log: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Force the guest resolver onto a public DNS and verify it actually works.

    VirtualBox's NAT DNS proxy (10.0.2.3) forwards through the *host* resolver;
    if the host runs ``systemd-resolved`` (a loopback stub) the proxy has nothing
    to forward to and guest DNS silently breaks even though raw IP routing works.
    ``apt-get update`` exits 0 even when index fetches fail, so its return code
    proves nothing — resolution is re-verified explicitly with ``getent`` each
    round instead. Returns True once a real answer comes back.
    """
    for i in range(attempts):
        iface_out = runner("ip route show default | awk '{print $5; exit}'", timeout=30)
        iface = iface_out.strip().splitlines()[-1] if iface_out.strip() else "enp0s3"
        runner(
            f"sudo resolvectl dns {iface} 8.8.8.8 1.1.1.1 2>&1; "
            f"sudo resolvectl domain {iface} '~.' 2>&1",
            timeout=30,
        )
        check = runner("getent hosts archive.ubuntu.com 2>&1", timeout=15)
        log(f"[*] DNS check ({i + 1}/{attempts}, iface={iface}): {check.strip() or '(no output)'}")
        if re.search(r"\d+\.\d+\.\d+\.\d+", check):
            return True
        sleep(5)
    return False
