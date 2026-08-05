"""Runtime configuration.

Replaces the ``DEEPSEEK_API_KEY = ""``-in-source pattern and the interactive
``input()`` prompt with a single explicit precedence chain:

    explicit argument  >  environment variable  >  optional config file

A secret literal is never written to source, and an unattended run (CI, a batch
of trials) never blocks on a prompt. The interactive prompt still exists but is
opt-in via :func:`AgentConfig.resolve_api_key`, called only from the CLI.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Mapping

from .scope import Scope

# LLM backends. DeepSeek is the hosted planner; Ollama is the free local
# fallback. Keeping the mapping here (rather than an if/else in every main())
# means adding a backend is a one-line change.
# Each entry: base_url, the default model, and the known selectable models for
# that backend (first = default). `--model` still accepts any string — the list
# is what the CLI advertises and what `known_models()` validates a choice
# against — so a model the provider adds later works without a code change.
BACKENDS: dict[str, dict] = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-flash",
        # The legacy deepseek-chat / deepseek-reasoner ids were discontinued
        # 2026-07-24. Current ids: deepseek-flash = V4.1-Flash (cheapest, the
        # default here); deepseek-v4-pro = V4-Pro. Thinking vs non-thinking is now
        # a *mode* on one model (thinking is the default), not a separate id.
        "models": ["deepseek-flash", "deepseek-v4-pro"],
    },
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "gemma3:12b"},
    # Gemini via its OpenAI-compatible endpoint, so the same OpenAI client works.
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "model": "gemini-2.5-flash",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro"],
    },
}


def known_models(backend: str) -> list[str]:
    """Advertised model ids for a backend (empty if it pins no list)."""
    return list(BACKENDS.get(backend, {}).get("models", []))


@dataclass
class AgentConfig:
    """Everything a run needs, resolved once at startup."""

    backend: str = "deepseek"
    api_key: str = ""
    model: str = ""  # blank -> backend default
    # How the planner emits tasks: "text" parses a JSON object from the reply;
    # "schema" uses native function calling with a per-task response schema. The
    # ablation axis — flipped per run, like `backend`.
    planner_mode: str = "text"
    # Thinking-token cap forwarded to the Gemini backend (None = backend default,
    # 0 = thinking disabled). Ignored by backends without a reasoning passthrough.
    reasoning_budget: int | None = None
    # Carry state forward as a growing transcript so the stable system prompt /
    # range context is a cacheable prefix and only the per-turn delta is resent.
    cache_prompt: bool = False
    # Tri-state planner thinking toggle: None = backend default, True/False =
    # force on/off. See :meth:`resolved_thinking` for why DeepSeek defaults off.
    thinking: bool | None = None
    max_turns: int = 80
    snapshot_name: str = "clean"
    restore_on_exit: bool = True

    # Timeouts (seconds).
    cmd_timeout: int = 30
    run_timeout: int = 90
    scan_timeout: int = 60
    toolkit_timeout: int = 300
    planner_timeout: int = 120

    scope: Scope = field(default_factory=Scope)
    attacker_ip: str = "192.168.56.177"

    audit_dir: Path = field(default_factory=lambda: Path("runs"))

    # -- construction ----------------------------------------------------------

    @classmethod
    def from_sources(
        cls,
        *,
        cli: dict | None = None,
        env: Mapping[str, str] | None = None,
        config_file: str | Path | None = None,
    ) -> AgentConfig:
        """Build a config, applying file, then env, then CLI (highest wins).

        ``cli`` values of ``None`` are treated as "unset" and do not override.
        """
        env = env if env is not None else os.environ
        data: dict = {}

        if config_file:
            path = Path(config_file)
            if path.is_file():
                data.update(json.loads(path.read_text()))

        if env.get("DEEPSEEK_API_KEY"):
            data["api_key"] = env["DEEPSEEK_API_KEY"]
            data.setdefault("backend", "deepseek")
        if env.get("GEMINI_API_KEY"):
            data["api_key"] = env["GEMINI_API_KEY"]
            data.setdefault("backend", "gemini")
        if env.get("SOMBRA_BACKEND"):
            data["backend"] = env["SOMBRA_BACKEND"]
        if env.get("SOMBRA_PLANNER_MODE"):
            data["planner_mode"] = env["SOMBRA_PLANNER_MODE"]
        if env.get("SOMBRA_REASONING_BUDGET"):
            data["reasoning_budget"] = int(env["SOMBRA_REASONING_BUDGET"])
        if env.get("SOMBRA_CACHE_PROMPT"):
            data["cache_prompt"] = env["SOMBRA_CACHE_PROMPT"].lower() in ("1", "true", "yes", "on")
        if env.get("SOMBRA_THINKING"):
            data["thinking"] = env["SOMBRA_THINKING"].lower() in ("1", "true", "yes", "on")

        for key, value in (cli or {}).items():
            if value is not None:
                data[key] = value

        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    # -- derived ---------------------------------------------------------------

    def resolved_model(self) -> str:
        return self.model or BACKENDS[self.backend]["model"]

    def resolved_thinking(self) -> bool | None:
        """Whether to force the planner's thinking mode on/off (None = leave alone).

        An explicit ``thinking`` always wins. Otherwise DeepSeek defaults to OFF:
        deepseek-flash (V4.1) ships with thinking ON, which leaks non-JSON text
        into text-mode replies and makes the API reject schema mode's forced
        tool_choice — so the harness's structured planner needs it off unless the
        user opts in. Other backends keep their own default (None).
        """
        if self.thinking is not None:
            return self.thinking
        if self.backend == "deepseek":
            return False
        return None

    def base_url(self) -> str:
        return BACKENDS[self.backend]["base_url"]

    def uses_hosted_key(self) -> bool:
        return self.backend != "ollama"

    def resolve_api_key(self, *, interactive: bool = False) -> AgentConfig:
        """Return a copy with an api_key filled in.

        Ollama needs no real key. For a hosted backend, prompt only if
        ``interactive`` and nothing was supplied — otherwise leave it blank and
        let the caller fail loudly rather than silently blocking a batch run.
        """
        if not self.uses_hosted_key():
            return replace(self, api_key=self.api_key or "ollama")
        if self.api_key and "sk-your" not in self.api_key:
            return self
        if interactive:
            entered = input("DeepSeek API key: ").strip()
            return replace(self, api_key=entered)
        return self
