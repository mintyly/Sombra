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
from typing import Any, Mapping, Sequence

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
    tokens: int = 0
    turns_to_objective: int | None = None


class Engine:
    def __init__(
        self,
        ctx: TaskContext[Any],
        registry: Mapping[str, TaskFn],
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
        # Record exactly which planner produced this run — backend, concrete
        # model id, and emit mode — so the report and any batch analysis name the
        # model instead of inferring it. getattr keeps fake planners in tests
        # (which expose none of these) working.
        self.audit.event(
            "run_start",
            agent=self.audit.run_id,
            max_turns=max_turns,
            backend=getattr(self.ctx.config, "backend", None),
            model=getattr(self.planner, "model", None),
            planner_mode=getattr(self.planner, "mode", None),
            thinking=getattr(self.planner, "thinking", None),
        )

        turn = 0
        success = False
        last_task: str | None = None
        repeats = 0
        wasted = 0
        objective_turn: int | None = None

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
                    if success:
                        objective_turn = turn
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
                    objective_turn = turn
                    log.info("FLAG CAPTURED: %s (turn %d)", self.ctx.state.flag_content, turn)
                    self.audit.event("flag_captured", turn=turn, flag=self.ctx.state.flag_content)
                    break
                time.sleep(1)

            if not success:
                log.info("did not capture the flag in %d turns.", turn)
        finally:
            # tokens-per-run and turns-to-objective on the run_end line, so a batch
            # of trials is comparable straight from the JSONL (fake planners in
            # tests expose no usage, hence the getattr defaults).
            tokens = getattr(self.planner, "total_tokens", 0)
            self.audit.event(
                "run_end",
                success=success,
                turns=turn,
                turns_to_objective=objective_turn,
                tokens=tokens,
                prompt_tokens=getattr(self.planner, "prompt_tokens", 0),
                completion_tokens=getattr(self.planner, "completion_tokens", 0),
                cached_tokens=getattr(self.planner, "cached_tokens", 0),
            )
            # A successful run gets a human-readable Markdown companion to the
            # JSONL trail, rendered from the same event stream. Report failures
            # must not mask the run's own result or skip snapshot restore, so
            # this is best-effort and logged, never raised.
            if success:
                try:
                    report_path = self.audit.write_report()
                    log.info("run succeeded; vulnerability report written to %s", report_path)
                except Exception:  # noqa: BLE001 - reporting must never abort cleanup
                    log.exception("failed to write vulnerability report")
            if restore_on_exit:
                self.ctx.vbox.restore_snapshots(self.range_vms)

        return RunResult(
            success=success,
            turns=turn,
            flag=self.ctx.state.flag_content,
            run_id=self.audit.run_id,
            tokens=getattr(self.planner, "total_tokens", 0),
            turns_to_objective=objective_turn,
        )
