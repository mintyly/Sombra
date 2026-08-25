"""The LLM planner.

One request per turn: the system prompt (the task menu + rules) plus the current
state summary. Returns a parsed task dict, or ``None`` on any API/JSON error so
the engine can distinguish a real planner *decision* from a transport hiccup and
not spend a turn of the budget on the latter.

The OpenAI client is injected rather than constructed here, so the engine can be
driven by a fake planner in tests with no network and no key.

Two optional, per-run levers (both ablation axes, off by default so a baseline
run is byte-identical to the old behaviour):

* ``reasoning_budget`` — a thinking-token cap forwarded to the Gemini backend via
  its OpenAI-compatible ``extra_body`` passthrough. ``0`` disables thinking;
  higher values trade latency/tokens for deliberation.
* ``cache_prompt`` — keep the system prompt (task menu + rules + range context)
  as a byte-stable prefix and carry the state forward as a growing transcript, so
  each turn sends only the *delta* since the previous turn as fresh input. The
  stable prefix is what the provider's context cache can hit; only the small
  per-turn delta is billed at the full input rate.

Token usage reported by the backend is accumulated across the run so the engine
can record tokens-per-run in the audit trail.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from .audit import get_logger

log = get_logger()


def _loads_first_object(content: str) -> dict:
    """Parse the first JSON object in a reply, tolerating trailing junk.

    ``json.loads`` requires the whole string to be exactly one JSON value, so a
    model that appends anything after the object — a second object, a stray
    newline, leaked chain-of-thought — raises ``Extra data: ...``. ``raw_decode``
    instead parses one value from the front and reports where it stopped; we keep
    that value and drop the rest. Leading prose is still rejected (there is no
    object to anchor to), which is the right call — that is a malformed reply,
    not trailing noise.
    """
    return json.JSONDecoder().raw_decode(content.lstrip())[0]


class ChatClient(Protocol):
    """The slice of the OpenAI client the planner actually uses."""

    class chat:  # noqa: N801 - mirrors the real client's attribute shape
        class completions:  # noqa: N801 - same reason, nested class needs its own suppression
            @staticmethod
            def create(**kwargs: Any) -> Any: ...


class Planner:
    def __init__(
        self,
        client: Any,
        model: str,
        system_prompt: str,
        timeout: int = 120,
        mode: str = "text",
        tools: list | None = None,
        reasoning_budget: int | None = None,
        cache_prompt: bool = False,
        thinking: bool | None = None,
    ):
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout
        # "text": parse a JSON object from the reply text. "schema": native
        # function calling, where the chosen function name is the task. Both
        # paths return the same {"task": ..., ...args} dict, so nothing
        # downstream (engine, audit, tasks) can tell which produced it.
        self.mode = mode
        self.tools = tools
        self.reasoning_budget = reasoning_budget
        self.cache_prompt = cache_prompt
        # Tri-state thinking toggle: None = leave the backend's default alone,
        # True/False = force DeepSeek's `thinking` on/off via extra_body. Needed
        # because deepseek-flash (V4.1) defaults thinking ON, which both leaks
        # non-JSON text into text-mode replies and forbids schema mode's forced
        # tool_choice ("Thinking mode does not support this tool_choice").
        self.thinking = thinking

        # Transcript carried forward only in cache mode: the system prompt stays
        # the stable (cacheable) prefix, these are the user-delta / assistant-task
        # pairs appended each turn. Empty in stateless mode.
        self._history: list[dict] = []
        self._prev_summary: str | None = None

        # Usage accumulated across the run (0 when the backend reports none).
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.cached_tokens = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def next_task(self, state_summary: str) -> dict | None:
        user_content = self._user_content(state_summary)
        messages = [
            {"role": "system", "content": self.system_prompt},
            *self._history,
            {"role": "user", "content": user_content},
        ]
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages, "timeout": self.timeout}
        extra_body: dict[str, Any] = {}
        if self.reasoning_budget is not None:
            # Gemini's OpenAI-compatible endpoint takes a provider passthrough
            # under a nested ``extra_body``; other backends simply never set this.
            extra_body["extra_body"] = {
                "google": {"thinking_config": {"thinking_budget": self.reasoning_budget}}
            }
        if self.thinking is not None:
            # DeepSeek's OpenAI-compatible switch for thinking vs non-thinking.
            extra_body["thinking"] = {"type": "enabled" if self.thinking else "disabled"}
        if extra_body:
            kwargs["extra_body"] = extra_body
        try:
            log.info("waiting for planner (%s, %s)...", self.model, self.mode)
            if self.mode == "schema":
                resp = self.client.chat.completions.create(
                    tools=self.tools,
                    tool_choice="required",
                    **kwargs,
                )
                self._record_usage(resp)
                call = resp.choices[0].message.tool_calls[0]
                task = {"task": call.function.name, **json.loads(call.function.arguments)}
            else:
                resp = self.client.chat.completions.create(
                    response_format={"type": "json_object"},
                    **kwargs,
                )
                self._record_usage(resp)
                task = _loads_first_object(resp.choices[0].message.content)
        except Exception as exc:  # noqa: BLE001 - deliberately broad; logged then reported as no-task
            log.warning("planner error: %s", exc)
            return None

        self._commit(state_summary, user_content, task)
        return task

    # -- prompt caching --------------------------------------------------------

    def _user_content(self, state_summary: str) -> str:
        """The per-turn user message.

        Stateless mode (and the first cached turn) sends the full summary. Later
        cached turns send only the lines that changed since the previous turn —
        the prior turns already live in ``_history`` as the cacheable prefix.
        """
        if not self.cache_prompt or self._prev_summary is None:
            return f"Current state:\n{state_summary}\n\nWhat task next?"
        delta = self._delta(self._prev_summary, state_summary)
        body = delta if delta else "(no change since your last turn)"
        return f"State changes since your last turn:\n{body}\n\nWhat task next?"

    @staticmethod
    def _delta(prev: str, curr: str) -> str:
        """Lines present in the current summary but not the previous one."""
        prev_lines = set(prev.splitlines())
        return "\n".join(line for line in curr.splitlines() if line not in prev_lines)

    def _commit(self, state_summary: str, user_content: str, task: dict) -> None:
        """After a successful turn, advance the cached transcript."""
        if not self.cache_prompt:
            return
        self._history.append({"role": "user", "content": user_content})
        self._history.append({"role": "assistant", "content": json.dumps(task)})
        self._prev_summary = state_summary

    # -- usage -----------------------------------------------------------------

    def _record_usage(self, resp: Any) -> None:
        usage = getattr(resp, "usage", None)
        if usage is None:
            return
        self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
        self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0
        # Cache hits, when the backend reports them, live under prompt_tokens_details.
        details = getattr(usage, "prompt_tokens_details", None)
        if details is not None:
            self.cached_tokens += getattr(details, "cached_tokens", 0) or 0


def make_client(base_url: str, api_key: str):
    """Construct a real OpenAI-compatible client. Imported lazily so the rest of
    the package (and its tests) don't need the ``openai`` dependency present."""
    from openai import OpenAI

    return OpenAI(base_url=base_url, api_key=api_key)
