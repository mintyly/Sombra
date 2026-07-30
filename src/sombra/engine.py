"""The turn loop.

This is the single copy of the plan -> execute -> update -> repeat loop that used
to be pasted (with drift) into every agent's ``main()``. An agent is now just a
:class:`~sombra.tasks.TaskContext`, a task registry, and a :class:`Planner`; the
engine drives them identically.

The loop's two non-obvious properties, both preserved from the originals:

* A malformed/absent planner response is an API hiccup, not a decision, so it
  does not spend a turn of the budget — but a persistently broken planner is
  hard-capped so it can't spin forever.
* Snapshot restore runs in a ``finally`` so an interrupted run still leaves the
  range clean for the next one.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence

from .audit import AuditLog, get_logger
from .planner import Planner
from .tasks import TaskContext, TaskFn

log = get_logger()

_DONE = {"done", "finished", "complete", "stop"}
_MAX_WASTED = 20


@dataclass
class RunResult:
    success: bool
    turns: int
    flag: str | None
    run_id: str


class Engine:
    def __init__(
        self,
        ctx: TaskContext,
        registry: dict[str, TaskFn],
        planner: Planner,
        range_vms: Sequence[str],
        audit: AuditLog,
    ):
        self.ctx = ctx
        self.registry = registry
        self.planner = planner
        self.range_vms = list(range_vms)
        self.audit = audit

    def run(self, max_turns: int, restore_on_exit: bool = True) -> RunResult:
        self.ctx.vbox.ensure_snapshots(self.range_vms)
        self.audit.event("run_start", agent=self.audit.run_id, max_turns=max_turns)

        turn = 0
        success = False
        last_task: str | None = None
        repeats = 0
        wasted = 0

        try:
            while turn < max_turns:
                task = self.planner.next_task(self.ctx.state.summary())
                if not task or not task.get("task"):
                    wasted += 1
                    log.warning("no valid task from planner (%d/%d wasted)", wasted, _MAX_WASTED)
                    if wasted >= _MAX_WASTED:
                        log.error("planner persistently returning invalid JSON; giving up.")
                        break
                    time.sleep(2)
                    continue
                wasted = 0
                turn += 1

                name = task["task"]
                repeats = repeats + 1 if name == last_task else 0
                last_task = name

                log.info("TURN %d | %s%s | %s", turn, name,
                         f" (x{repeats + 1})" if repeats else "", task.get("rationale", ""))
                self.audit.event("planner_task", turn=turn, task=name,
                                 rationale=task.get("rationale", ""), repeats=repeats)

                if name in _DONE:
                    log.info("planner signaled completion.")
                    success = self.ctx.state.flag_found
                    break

                fn = self.registry.get(name)
                if fn is None:
                    log.warning("unknown task: %s", name)
                    continue

                result = fn(self.ctx, task)
                status = "OK" if result.get("success") else "FAIL"
                log.info("  -> %s: %s", status, result.get("output", "").splitlines()[:1])

                if result.get("flag_captured"):
                    success = True
                    log.info("FLAG CAPTURED: %s (turn %d)", self.ctx.state.flag_content, turn)
                    self.audit.event("flag_captured", turn=turn, flag=self.ctx.state.flag_content)
                    break
                time.sleep(1)

            if not success:
                log.info("did not capture the flag in %d turns.", turn)
        finally:
            self.audit.event("run_end", success=success, turns=turn)
            if restore_on_exit:
                self.ctx.vbox.restore_snapshots(self.range_vms)

        return RunResult(success=success, turns=turn, flag=self.ctx.state.flag_content, run_id=self.audit.run_id)
