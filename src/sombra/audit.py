"""Logging and the per-run audit trail.

Two outputs from one place:

* A human-readable console logger (levelled, replacing scattered ``print``).
* A machine-readable JSONL audit file: one line per planner decision and per
  executed command, timestamped. For a tool that runs LLM-chosen shell against a
  target this is not a nicety — it is the accountability record of exactly what
  was done, and it doubles as the raw material for the paper's reproducibility
  and per-turn analysis (turns-to-flag, task-mix, repeat rate).

A successful run additionally gets a Markdown *vulnerability report* rendered
from the very same records (see :mod:`sombra.report`): the JSONL is for machines,
the ``.md`` is the step-by-step narrative a human reads. Both come from one event
stream, so they can never disagree about what happened.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def get_logger(name: str = "sombra", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


@dataclass
class AuditLog:
    """Append-only JSONL record of a single run.

    Every event is both written to the JSONL file and retained in
    :attr:`records`, so the Markdown report can be rendered at run end from the
    in-memory stream without re-reading (and re-parsing) the file.
    """

    path: Path
    run_id: str
    records: list[dict] = field(default_factory=list)

    @classmethod
    def create(cls, audit_dir: Path, agent: str) -> AuditLog:
        audit_dir.mkdir(parents=True, exist_ok=True)
        run_id = f"{agent}-{time.strftime('%Y%m%d-%H%M%S')}"
        return cls(path=audit_dir / f"{run_id}.jsonl", run_id=run_id)

    @property
    def report_path(self) -> Path:
        """Companion ``.md`` report path (same stem as the JSONL trail)."""
        return self.path.with_suffix(".md")

    def event(self, kind: str, **fields: Any) -> None:
        record = {"ts": time.time(), "run_id": self.run_id, "kind": kind, **fields}
        self.records.append(record)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def write_report(self) -> Path:
        """Render the retained events to a human-readable Markdown report.

        Deferred import keeps the report renderer out of the hot path for runs
        that never call it, and avoids an import cycle (``report`` reads nothing
        from here but keeps the dependency one-directional).
        """
        from .report import render_report

        self.report_path.write_text(render_report(self.records), encoding="utf-8")
        return self.report_path
