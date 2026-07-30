"""The LLM planner.

One request per turn: the system prompt (the task menu + rules) plus the current
state summary. Returns a parsed task dict, or ``None`` on any API/JSON error so
the engine can distinguish a real planner *decision* from a transport hiccup and
not spend a turn of the budget on the latter.

The OpenAI client is injected rather than constructed here, so the engine can be
driven by a fake planner in tests with no network and no key.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .audit import get_logger

log = get_logger()


class ChatClient(Protocol):
    """The slice of the OpenAI client the planner actually uses."""

    class chat:  # noqa: N801 - mirrors the real client's attribute shape
        class completions:  # noqa: N801 - same reason, nested class needs its own suppression
            @staticmethod
            def create(**kwargs: Any) -> Any: ...


class Planner:
    def __init__(self, client: Any, model: str, system_prompt: str, timeout: int = 120):
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout

    def next_task(self, state_summary: str) -> dict | None:
        try:
            log.info("waiting for planner (%s)...", self.model)
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": f"Current state:\n{state_summary}\n\nWhat task next? JSON only."},
                ],
                response_format={"type": "json_object"},
                timeout=self.timeout,
            )
            return json.loads(resp.choices[0].message.content)
        except Exception as exc:  # noqa: BLE001 - deliberately broad; logged then reported as no-task
            log.warning("planner error: %s", exc)
            return None


def make_client(base_url: str, api_key: str):
    """Construct a real OpenAI-compatible client. Imported lazily so the rest of
    the package (and its tests) don't need the ``openai`` dependency present."""
    from openai import OpenAI

    return OpenAI(base_url=base_url, api_key=api_key)
