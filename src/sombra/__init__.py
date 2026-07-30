"""Sombra — blind autonomous LLM red-team harness.

A planner/executor architecture (loosely after Incalmo, arXiv:2501.16466): an LLM
planner emits structured tasks, deterministic Python task-agents execute them
against an isolated cyber range, and a stateless-planner/evidence-anchored-state
loop drives the two. Four agents span an autonomy spectrum from a scripted chain
to a blind agent with nothing but a raw shell.
"""

from __future__ import annotations

from .config import AgentConfig
from .scope import Scope

__all__ = ["AgentConfig", "Scope", "__version__"]
__version__ = "1.0.0"
