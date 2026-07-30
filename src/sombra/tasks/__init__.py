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

from collections.abc import Callable
from dataclasses import dataclass

from ..audit import AuditLog, get_logger
from ..config import AgentConfig
from ..state import BaseState
from ..vbox import VBox

TaskFn = Callable[["TaskContext", dict], dict]


@dataclass
class TaskContext:
    """Everything a task needs, passed in rather than reached for globally."""

    state: BaseState
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
