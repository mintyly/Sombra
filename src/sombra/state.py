"""State services.

Every planner turn is a fresh, stateless LLM request. The *only* memory of what
has happened is whatever :meth:`summary` renders, so the summary is load-bearing:
it is both the agent's working memory and its defence against acting on stale
beliefs.

``BaseState`` holds the fields common to all agents; each subclass adds the
fields its task set needs and extends the summary. This removes the near-
duplicate ``StateService`` that appeared in all four scripts while keeping each
one's summary faithful.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BaseState:
    discovered_hosts: dict[str, dict] = field(default_factory=dict)
    flag_found: bool = False
    flag_content: str | None = None
    toolkit_installed: bool = False
    current_subnet: str = "192.168.56.0/24"

    def _host_lines(self) -> list[str]:
        lines = ["DISCOVERED STATE:"]
        if self.discovered_hosts:
            for ip, info in self.discovered_hosts.items():
                lines.append(f"  {ip}: open_ports={info.get('open_ports', [])}")
        else:
            lines.append("  No hosts discovered yet.")
        return lines

    def _footer_lines(self) -> list[str]:
        return [f"Flag captured: {self.flag_found}", f"Toolkit installed: {self.toolkit_installed}"]

    def summary(self) -> str:
        return "\n".join(self._host_lines() + self._footer_lines())


@dataclass
class WebState(BaseState):
    """State for the generic-shell web agent (bWAPP)."""

    # Each entry: {"command": str, "output": str}.
    command_history: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        lines = self._host_lines()
        lines.append(f"Commands run so far: {len(self.command_history)}")
        if self.command_history:
            earlier = self.command_history[-9:-1]
            if earlier:
                # A one-line digest of what each older command *actually returned*,
                # not just the command string. Without this, a false belief formed
                # several turns ago ("I uploaded a working webshell") is never
                # contradicted, because the output that would disprove it has
                # scrolled out of view. Cheap in tokens, closes a real
                # hallucination path.
                lines.append(
                    "Earlier commands with a short digest of what they actually returned "
                    "(verify against these before assuming something still holds):"
                )
                for h in earlier:
                    digest = " ".join(h["output"].split())[:120]
                    lines.append(f"  $ {h['command']}")
                    lines.append(f"    -> {digest}")
            last = self.command_history[-1]
            lines.append('Most recent command and its FULL result — do not re-run this to "check" it again:')
            lines.append(f"  $ {last['command']}")
            lines.append(f"  -> {last['output']}")
        lines += self._footer_lines()
        return "\n".join(lines)


@dataclass
class WinRMState(BaseState):
    """State for the WinRM/Windows agent."""

    tested_credentials: list[tuple] = field(default_factory=list)
    winrm_sessions: dict[str, bool] = field(default_factory=dict)
    host_credentials: dict[str, tuple] = field(default_factory=dict)
    executed_commands: list[str] = field(default_factory=list)
    found_files: list[str] = field(default_factory=list)
    flag_path: str | None = None
    webhost_running: bool = False
    webhost_port: int = 4443

    def summary(self) -> str:
        lines = ["DISCOVERED STATE:"]
        if self.discovered_hosts:
            for ip, info in self.discovered_hosts.items():
                winrm = " (WinRM authenticated)" if self.winrm_sessions.get(ip) else ""
                lines.append(
                    f"  {ip}: OS={info.get('os', 'unknown')}, "
                    f"ports={info.get('open_ports', [])}{winrm}"
                )
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


@dataclass
class ScriptedState(BaseState):
    """State for the scripted APT32-A chain (cradle_agent)."""

    hosts: dict[str, dict] = field(default_factory=dict)
    current_script_index: int = 0
    webhost_running: bool = False
    webhost_port: int = 8080
    backdoor_running: bool = False
    pywinrm_installed: bool = False
    callback_detected: bool = False
    callback_detail: str = ""
    compromise_verified: bool = False
    verification_evidence: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = ["DISCOVERED STATE:"]
        lines.append(f"Scripts executed: {self.current_script_index}")
        lines.append(f"Webhost running: {self.webhost_running}")
        lines.append(f"Backdoor running: {self.backdoor_running}")
        lines.append(f"pywinrm installed: {self.pywinrm_installed}")
        lines.append(f"Callback detected: {self.callback_detected}")
        lines.append(f"Compromise verified: {self.compromise_verified}")
        lines.append(f"Flag captured: {self.flag_found}")
        return "\n".join(lines)
