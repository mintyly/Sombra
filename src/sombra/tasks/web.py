"""Task agents for the generic-shell web target (bWAPP).

The design principle here is *no vulnerability-named primitives*: the planner
gets ``install_toolkit``, ``scan_network`` and one generic ``run_command`` shell,
and must find and chain a real bug itself. This is the most autonomous of the
four agents.
"""

from __future__ import annotations

from functools import partial

from ..flags import find_flag
from ..net import clear_apt_locks, heal_dns, parse_nmap
from ..state import WebState
from . import TaskContext

# Known intentionally-vulnerable training-app directory names, in their real
# casing. Generic wordlists are lowercase and miss an app folder with unusual
# capitalisation on a case-sensitive filesystem, no matter how large they are.
_VULN_APP_NAMES = [
    "bWAPP", "BWAPP", "bwapp", "DVWA", "dvwa", "Mutillidae", "mutillidae",
    "WebGoat", "webgoat", "Juice-Shop", "juice-shop", "Gruyere", "gruyere",
    "bodgeit", "BodgeIt", "xvwa", "XVWA", "hackazon", "VAmPI",
    "security-shepherd", "WackoPicko", "wackopicko", "NodeGoat", "railsgoat",
    "altoro", "testfire", "peruggia",
]

_WEB_PORTS = "21,22,80,443,3306,8080"


def _ensure_toolkit(ctx: TaskContext[WebState]) -> bool:
    if ctx.state.toolkit_installed:
        return True

    run = partial(ctx.vbox.guest_bash, ctx.attacker_vm)
    clear_apt_locks(run, timeout=ctx.config.cmd_timeout)

    if not heal_dns(run, log=ctx.log.info):
        ctx.log.warning("DNS never came up — toolkit install will likely fail too.")

    ctx.log.info("Installing web-attack toolkit (nmap, curl, sqlmap, dirb, nikto, python3)...")
    run(
        "export DEBIAN_FRONTEND=noninteractive; "
        "sudo -E apt-get update -qq 2>&1; "
        "sudo -E apt-get install -y -qq nmap curl sqlmap dirb nikto python3-pip 2>&1 && "
        "pip3 install requests -q 2>&1",
        timeout=ctx.config.toolkit_timeout,
    )
    check = run(
        "command -v sqlmap >/dev/null && command -v curl >/dev/null && "
        "command -v nmap >/dev/null && echo ALL_OK || echo MISSING"
    )
    if "ALL_OK" not in check:
        ctx.log.warning("Toolkit install failed (check=%s).", check.strip())
        return False

    ctx.state.toolkit_installed = True
    # dirb bundles big.txt (~20k words); no network fetch, so nothing to 404.
    heredoc = "\n".join(_VULN_APP_NAMES)
    run(f"cat > /tmp/vuln-app-names.txt << 'SOMBRA_EOF'\n{heredoc}\nSOMBRA_EOF")
    ctx.log.info("Toolkit installed; wrote /tmp/vuln-app-names.txt.")
    return True


def install_toolkit(ctx: TaskContext[WebState], task: dict) -> dict:
    if _ensure_toolkit(ctx):
        return {"success": True, "output": "Toolkit installed: nmap, curl, sqlmap, dirb, nikto, python3+requests"}
    return {"success": False, "output": "Toolkit installation failed. Check network connectivity."}


def scan_network(ctx: TaskContext[WebState], task: dict) -> dict:
    if not ctx.state.toolkit_installed:
        return {"success": False, "output": "nmap not installed. Run 'install_toolkit' first."}

    subnet = ctx.state.current_subnet
    out = ctx.vbox.guest_bash(
        ctx.attacker_vm,
        f"nmap -T4 -Pn -p {_WEB_PORTS} --exclude {ctx.scope.nmap_exclude_arg()} --open {subnet} 2>&1",
        timeout=ctx.config.scan_timeout,
    )
    if "command not found" in out.lower():
        return {"success": False, "output": f"nmap not found. Install toolkit first.\n{out[:200]}"}

    before = len(ctx.state.discovered_hosts)
    for ip, info in parse_nmap(out, ctx.scope).items():
        existing = ctx.state.discovered_hosts.setdefault(ip, {"open_ports": []})
        for port in info["open_ports"]:
            if port not in existing["open_ports"]:
                existing["open_ports"].append(port)
    found = len(ctx.state.discovered_hosts) - before

    if found == 0:
        # Toggle rather than switch one-way, so an empty or truncated scan can
        # never permanently strand the agent off the subnet the target is on.
        prev = ctx.state.current_subnet
        ctx.state.current_subnet = "192.168.57.0/24" if prev == "192.168.56.0/24" else "192.168.56.0/24"
        return {"success": True, "output": f"No new hosts on {prev}. Switching to {ctx.state.current_subnet}.\n{out[:400]}"}

    parts = [f"Found {found} new host(s) on {subnet}:"]
    parts += [f"  {ip}: ports={info.get('open_ports', [])}" for ip, info in ctx.state.discovered_hosts.items()]
    return {"success": True, "output": "\n".join(parts) + f"\n\nRaw output:\n{out[:400]}"}


def run_command(ctx: TaskContext[WebState], task: dict) -> dict:
    """Run arbitrary bash on the attacker box — the primary recon + exploit tool."""
    command = task.get("command", "")
    if not command:
        return {"success": False, "output": "Must supply a 'command' field."}

    ok, reason = ctx.scope.check_command(command)
    if not ok:
        ctx.audit.event("scope_refusal", command=command, reason=reason)
        return {"success": False, "output": reason}

    out = ctx.vbox.guest_bash(ctx.attacker_vm, command, timeout=ctx.config.run_timeout)
    truncated = out[:1500]
    ctx.state.command_history.append({"command": command, "output": truncated})
    ctx.audit.event("run_command", command=command, output=truncated)

    flag = find_flag(out)
    if flag:
        ctx.state.flag_found = True
        ctx.state.flag_content = flag
        return {"success": True, "output": truncated, "flag_captured": True}
    return {"success": True, "output": truncated}


def done(ctx: TaskContext[WebState], task: dict) -> dict:
    return {"success": True, "output": "Planner signaled completion."}


REGISTRY = {
    "install_toolkit": install_toolkit,
    "scan_network": scan_network,
    "run_command": run_command,
    "done": done,
    "finished": done,
    "complete": done,
    "stop": done,
}
