"""Planner task menus as function-calling schemas.

The schema-constrained arm of the planner ablation (see :mod:`sombra.planner`)
needs a machine-readable twin of the task menu that :mod:`sombra.prompts` states
in prose. Each agent's builder returns a list of OpenAI-style *tool* declarations
— one function per registry task — so the model picks its next task by calling a
function whose name *is* the task and whose arguments are schema-constrained.

The function names and argument keys must match exactly what the task functions
read from the task dict in :mod:`sombra.tasks`; a mismatch would surface a task
the engine can dispatch but the handler can't read. ``rationale`` is on every
function so the audit log carries the same "why" string it does in text mode.
"""

from __future__ import annotations

from typing import Any

# Every task records a rationale, mirroring the text-mode prompt's instruction.
_RATIONALE = {"type": "string", "description": "Why this task, in one sentence."}


def _fn(name: str, description: str, *, properties: dict | None = None, required: list[str] | None = None) -> dict:
    """One OpenAI-style function declaration for a single task."""
    props: dict[str, Any] = {"rationale": _RATIONALE}
    props.update(properties or {})
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": props,
                # rationale is always expected; task-specific args add to it.
                "required": ["rationale", *(required or [])],
            },
        },
    }


def web_tools() -> list[dict]:
    return [
        _fn("install_toolkit", "Install nmap, curl, sqlmap, dirb, nikto, python3. Required first."),
        _fn("scan_network", "Scan the local subnet for live hosts and open ports."),
        _fn(
            "run_command",
            "Run arbitrary bash on the attacker box — primary recon and exploit tool.",
            properties={"command": {"type": "string", "description": "The bash command to run."}},
            required=["command"],
        ),
        _fn("done", "Signal mission complete."),
    ]


def winrm_tools() -> list[dict]:
    """Shared by the blind and guided WinRM agents — same task registry."""
    return [
        _fn("install_toolkit", "Install nmap, pywinrm, curl, netcat, python3-pip. Required first."),
        _fn("scan_network", "Scan the local subnet for live hosts and open ports."),
        _fn(
            "test_winrm",
            "Try a username/password pair against WinRM (5985) on a discovered host.",
            properties={
                "username": {"type": "string"},
                "password": {"type": "string"},
                "target_ip": {"type": "string", "description": "Host to target; omit to auto-pick a 5985 host."},
            },
            required=["username", "password"],
        ),
        _fn(
            "execute_powershell",
            "Run PowerShell on a host you've authenticated to.",
            properties={
                "command": {"type": "string", "description": "The PowerShell command to run."},
                "target_ip": {"type": "string", "description": "Host to target; omit for the authenticated host."},
            },
            required=["command"],
        ),
        _fn("find_flag", "Search a compromised host for a flag file; remembers the path if found."),
        _fn("read_flag", "Read the flag file that find_flag discovered."),
        _fn("start_webhost", "Start an HTTP server on your box (exfil)."),
        _fn("done", "Signal mission complete."),
    ]


def scripted_tools() -> list[dict]:
    return [
        _fn("check_webhost", "Check whether the C2 web listener is running."),
        _fn("start_webhost", "Start the C2 web listener."),
        _fn("start_backdoor", "Start the backdoor listener."),
        _fn("install_pywinrm", "Install the WinRM client library on the attack box."),
        _fn("execute_script", "Run the next script in the APT32-A chain (5 total, in order)."),
        _fn("check_callback", "Check whether the victim has called back."),
        _fn("check_flag", "Read flag.txt from the victim desktop."),
        _fn("verify_compromise", "Independently confirm the victim is compromised."),
        _fn("done", "Signal mission complete."),
    ]
