"""Task agents.

A *task* is a deterministic function ``(ctx, task_dict) -> result_dict``. The
planner names a task and supplies any arguments inside ``task_dict``; the task
pulls what it needs from there. Results are dicts with at least ``success`` and
``output``; ``flag_captured=True`` ends the run.

Grouping tasks by target (:mod:`web`, :mod:`winrm`, :mod:`scripted`) keeps each
agent's registry small and explicit while sharing the context object and the
common plumbing underneath.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar

from ..audit import AuditLog, get_logger
from ..config import AgentConfig
from ..state import BaseState
from ..vbox import VBox

# Generic over the concrete state type so each task module can annotate its own
# functions as TaskContext[WinRMState] / TaskContext[WebState] / TaskContext[ScriptedState]
# and get real attribute checking on ctx.state, instead of every task module's
# state access being erased to the common BaseState. The registry itself is kept
# in terms of TaskContext[Any]: the dict of task functions is inherently
# heterogeneous (each agent's registry only ever receives its own state type at
# runtime), and Any is what lets mypy accept a Callable[[TaskContext[WinRMState], ...]]
# wherever a Callable[[TaskContext[Any], ...]] is expected without re-litigating
# Callable parameter contravariance for a pattern that is correct by construction.
StateT = TypeVar("StateT", bound=BaseState)

TaskFn = Callable[["TaskContext[Any]", dict], dict]


@dataclass
class TaskContext(Generic[StateT]):
    """Everything a task needs, passed in rather than reached for globally."""

    state: StateT
    vbox: VBox
    config: AgentConfig
    vms: dict[str, str]          # role -> VM name
    audit: AuditLog
    log = get_logger()

    @property
    def attacker_vm(self) -> str:
        return self.vms["attacker"]

    @property
    def scope(self):
        return self.config.scope
