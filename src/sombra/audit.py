"""Logging and the per-run audit trail.

Two outputs from one place:

* A human-readable console logger (levelled, replacing scattered ``print``).
* A machine-readable JSONL audit file: one line per planner decision and per
  executed command, timestamped. For a tool that runs LLM-chosen shell against a
  target this is not a nicety — it is the accountability record of exactly what
  was done, and it doubles as the raw material for the paper's reproducibility
  and per-turn analysis (turns-to-flag, task-mix, repeat rate).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
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
    """Append-only JSONL record of a single run."""

    path: Path
    run_id: str

    @classmethod
    def create(cls, audit_dir: Path, agent: str) -> AuditLog:
        audit_dir.mkdir(parents=True, exist_ok=True)
        run_id = f"{agent}-{time.strftime('%Y%m%d-%H%M%S')}"
        return cls(path=audit_dir / f"{run_id}.jsonl", run_id=run_id)

    def event(self, kind: str, **fields: Any) -> None:
        record = {"ts": time.time(), "run_id": self.run_id, "kind": kind, **fields}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
