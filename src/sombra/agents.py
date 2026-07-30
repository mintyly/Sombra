"""Agent specifications.

Each of the four agents is fully described by a small spec: which VM roles it
needs, which state class, which task registry, which prompt, and a couple of
defaults. The factory wires that spec onto the shared core and runs it. Adding a
fifth agent is a spec entry, not another 600-line copy of the loop.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from . import prompts
from .audit import AuditLog, get_logger
from .config import AgentConfig
from .engine import Engine, RunResult
from .planner import Planner, make_client
from .state import BaseState, ScriptedState, WebState, WinRMState
from .tasks import TaskContext, TaskFn
from .tasks import scripted as scripted_tasks
from .tasks import web as web_tasks
from .tasks import winrm as winrm_tasks
from .vbox import VBox, resolve_vm_names

log = get_logger()


@dataclass
class AgentSpec:
    name: str
    roles: Sequence[str]           # VM roles to resolve; first-listed attacker role must be "attacker"
    attacker_role: str
    state_cls: type[BaseState]
    registry: dict[str, TaskFn]
    prompt_fn: Callable[[str], str]
    default_max_turns: int = 80
    range_roles: Sequence[str] = field(default=())  # which resolved VMs get snapshotted

    def range_vms(self, vms: dict[str, str]) -> list[str]:
        roles = self.range_roles or self.roles
        return [vms[r] for r in roles]


AGENTS: dict[str, AgentSpec] = {
    "bwapp": AgentSpec(
        name="bwapp",
        roles=("attacker", "bwapp"),
        attacker_role="attacker",
        state_cls=WebState,
        registry=web_tasks.REGISTRY,
        prompt_fn=prompts.web_prompt,
        default_max_turns=80,
    ),
    "winrm": AgentSpec(
        name="winrm",
        roles=("attacker", "router", "victim"),
        attacker_role="attacker",
        state_cls=WinRMState,
        registry=winrm_tasks.REGISTRY,
        prompt_fn=prompts.winrm_blind_prompt,
        default_max_turns=40,
    ),
    "winrm-guided": AgentSpec(
        name="winrm-guided",
        roles=("attacker", "router", "victim"),
        attacker_role="attacker",
        state_cls=WinRMState,
        registry=winrm_tasks.REGISTRY,
        prompt_fn=prompts.winrm_guided_prompt,
        default_max_turns=40,
    ),
    "scripted": AgentSpec(
        name="scripted",
        roles=("attacker", "router", "victim"),
        attacker_role="attacker",
        state_cls=ScriptedState,
        registry=scripted_tasks.REGISTRY,
        prompt_fn=prompts.scripted_prompt,
        default_max_turns=40,
    ),
}


def build_engine(spec: AgentSpec, config: AgentConfig, vms: dict[str, str]) -> Engine:
    """Wire a spec + resolved config + resolved VM names into a runnable Engine."""
    vbox = VBox(snapshot_name=config.snapshot_name, default_timeout=config.cmd_timeout)
    audit = AuditLog.create(config.audit_dir, spec.name)

    # normalise the attacker role to the key the tasks expect ("attacker")
    resolved = dict(vms)
    resolved["attacker"] = vms[spec.attacker_role]

    ctx = TaskContext(state=spec.state_cls(), vbox=vbox, config=config, vms=resolved, audit=audit)
    client = make_client(config.base_url(), config.api_key)
    planner = Planner(client, config.resolved_model(), spec.prompt_fn(config.attacker_ip), config.planner_timeout)
    return Engine(ctx, spec.registry, planner, spec.range_vms(resolved), audit)


def run_agent(agent_name: str, config: AgentConfig, picker=input) -> RunResult:
    """Resolve VMs interactively, build, and run an agent end to end."""
    spec = AGENTS[agent_name]
    vbox = VBox(snapshot_name=config.snapshot_name, default_timeout=config.cmd_timeout)
    vms = resolve_vm_names(spec.roles, vbox.running_vms(), picker=picker)
    log.info("Resolved VMs: %s", vms)
    engine = build_engine(spec, config, vms)
    return engine.run(max_turns=config.max_turns, restore_on_exit=config.restore_on_exit)
