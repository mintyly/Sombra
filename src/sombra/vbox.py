"""VirtualBox transport layer.

All ``VBoxManage`` interaction lives here, behind a small class, instead of being
copy-pasted (with drift) into every agent. Agents and tasks receive a
:class:`VBox` instance and never shell out to ``VBoxManage`` themselves.

The host-side command composition uses ``shlex.quote`` on every interpolated VM
name and bash payload. The guest command itself is arbitrary by design — that is
the point of the harness — but the *host* wrapper around it is not a place to be
sloppy about quoting.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from typing import Sequence

from .audit import get_logger

log = get_logger()


class VBox:
    def __init__(self, snapshot_name: str = "clean", default_timeout: int = 30):
        self.snapshot_name = snapshot_name
        self.default_timeout = default_timeout

    # -- raw host execution ----------------------------------------------------

    def host_exec(self, command: str, timeout: int | None = None) -> tuple[str, str, int]:
        """Run a command on the host (earthquake).

        ``errors="replace"`` because once the agent pulls back raw file/HTTP/
        binary content (LFI reads, PowerShell output) stdout will eventually
        contain bytes that are not valid UTF-8; strict decoding would crash the
        whole harness on the first bad byte.
        """
        timeout = timeout or self.default_timeout
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 10,
        )
        return result.stdout, result.stderr, result.returncode

    # -- guest execution -------------------------------------------------------

    def guest_bash(self, vm: str, bash_command: str, timeout: int | None = None) -> str:
        """Run bash inside a Linux guest via guestcontrol."""
        timeout = timeout or self.default_timeout
        vm_cmd = (
            f"timeout {timeout} "
            f"VBoxManage guestcontrol {shlex.quote(vm)} run "
            f"--username vagrant --password vagrant "
            f"--exe /bin/bash -- -c {shlex.quote(bash_command)}"
        )
        out, err, _ = self.host_exec(vm_cmd, timeout=timeout)
        result = out + err
        return "[TIMEOUT]" if "timed out" in result.lower() else result

    def guest_cmd(self, vm: str, cmd_command: str, timeout: int | None = None) -> str:
        """Run a command inside a Windows guest via cmd.exe."""
        timeout = timeout or self.default_timeout
        vm_cmd = (
            f"timeout {timeout} "
            f"VBoxManage guestcontrol {shlex.quote(vm)} run "
            f"--username vagrant --password vagrant "
            f'--exe "C:\\Windows\\System32\\cmd.exe" -- cmd.exe /c {shlex.quote(cmd_command)}'
        )
        out, err, _ = self.host_exec(vm_cmd, timeout=timeout)
        return out + err

    # -- snapshot lifecycle ----------------------------------------------------

    def ensure_snapshots(self, vms: Sequence[str]) -> None:
        for vm in vms:
            out, _, _ = self.host_exec(f"VBoxManage snapshot {shlex.quote(vm)} list")
            if f'"{self.snapshot_name}"' in out or f"Name: {self.snapshot_name}" in out:
                continue
            log.info("Taking baseline snapshot of %s", vm)
            self.host_exec(f"VBoxManage snapshot {shlex.quote(vm)} take {shlex.quote(self.snapshot_name)}")

    def restore_snapshots(self, vms: Sequence[str]) -> None:
        log.info("Restoring VMs to clean snapshot...")
        for vm in vms:
            self.host_exec(f"VBoxManage controlvm {shlex.quote(vm)} poweroff || true")
        time.sleep(3)
        for vm in vms:
            self.host_exec(f"VBoxManage snapshot {shlex.quote(vm)} restore {shlex.quote(self.snapshot_name)}")
        time.sleep(2)
        for vm in vms:
            self.host_exec(f"VBoxManage startvm {shlex.quote(vm)} --type headless")
        log.info("Restore complete.")

    # -- discovery -------------------------------------------------------------

    def running_vms(self) -> list[str]:
        out, err, _ = self.host_exec("VBoxManage list runningvms")
        return [line.split('"')[1] for line in (out + err).splitlines() if '"' in line]


def resolve_vm_names(roles: Sequence[str], vms: Sequence[str], picker=input) -> dict[str, str]:
    """Interactively map role labels to running VM names.

    Accepts an index or a unique name substring per role. ``picker`` is injected
    so this can be driven non-interactively in tests.
    """
    if not vms:
        raise RuntimeError("No running VMs found. Run 'vagrant up' first.")

    print("\n[*] Running VMs:")
    for i, name in enumerate(vms):
        print(f"    [{i}] {name}")

    def pick(role: str) -> str:
        while True:
            choice = picker(f"    {role}: ").strip()
            if choice.isdigit() and 0 <= int(choice) < len(vms):
                return vms[int(choice)]
            matches = [vm for vm in vms if choice.lower() in vm.lower()]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                print(f"      Multiple matches: {matches}. Be more specific.")
            else:
                print(f"      No match for '{choice}'. Try again.")

    return {role: pick(role) for role in roles}
