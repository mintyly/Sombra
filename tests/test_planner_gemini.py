"""Planner against the Gemini backend with a fake OpenAI-compatible client.

No network, no key: a fake client matching the sliver of the OpenAI chat API the
planner uses stands in for a real Gemini call. Covers both ablation arms —
*text* (parse a JSON object from the reply) and *schema* (native function calling
with a per-task response schema) — and proves the central invariant: both arms
hand the engine the *same* ``{"task": ..., ...}`` dict. Also proves the resolved
model and state summary reach the client, and that a transport error becomes
``None`` rather than a crash, in either mode.
"""

from __future__ import annotations

import json
from typing import Any

from sombra.config import AgentConfig
from sombra.planner import Planner
from sombra.schemas import web_tools


def _fake_usage(prompt: int, completion: int, cached: int = 0):
    """An OpenAI-shaped usage object, with cached tokens under prompt_tokens_details."""
    details = type("Details", (), {"cached_tokens": cached})()
    return type(
        "Usage", (), {"prompt_tokens": prompt, "completion_tokens": completion, "prompt_tokens_details": details}
    )()


class FakeCompletion:
    """Text-mode return shape: choices[0].message.content holds a JSON string."""

    def __init__(self, content: str, usage=None):
        message = type("Msg", (), {"content": content, "tool_calls": None})()
        choice = type("Choice", (), {"message": message})()
        self.choices = [choice]
        self.usage = usage


class FakeToolCallCompletion:
    """Schema-mode return shape: choices[0].message.tool_calls[0].function.{name,arguments}."""

    def __init__(self, name: str, arguments: str, usage=None):
        function = type("Fn", (), {"name": name, "arguments": arguments})()
        tool_call = type("ToolCall", (), {"function": function})()
        message = type("Msg", (), {"content": None, "tool_calls": [tool_call]})()
        choice = type("Choice", (), {"message": message})()
        self.choices = [choice]
        self.usage = usage


class FakeChatClient:
    """OpenAI-compatible stand-in. Records call kwargs; returns a canned reply.

    ``reply`` drives text mode (a task dict serialized to message content);
    ``tool_call`` drives schema mode (a ``{"name", "arguments"}`` pair returned
    as a function call). ``error``, if set, is raised instead.
    """

    def __init__(
        self,
        *,
        reply: dict | None = None,
        tool_call: dict | None = None,
        error: Exception | None = None,
        usage=None,
    ):
        self._reply = reply
        self._tool_call = tool_call
        self._error = error
        self._usage = usage
        self.calls: list[dict[str, Any]] = []

        outer = self

        class _Completions:
            def create(self, **kwargs: Any):
                outer.calls.append(kwargs)
                if outer._error is not None:
                    raise outer._error
                if outer._tool_call is not None:
                    return FakeToolCallCompletion(
                        outer._tool_call["name"], json.dumps(outer._tool_call["arguments"]), usage=outer._usage
                    )
                return FakeCompletion(json.dumps(outer._reply), usage=outer._usage)

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


def _gemini_planner(
    client: FakeChatClient,
    *,
    mode: str = "text",
    tools: list | None = None,
    reasoning_budget: int | None = None,
    cache_prompt: bool = False,
    thinking: bool | None = None,
) -> Planner:
    cfg = AgentConfig(backend="gemini", planner_mode=mode)
    return Planner(
        client=client,
        model=cfg.resolved_model(),
        system_prompt="SYS",
        mode=mode,
        tools=tools,
        reasoning_budget=reasoning_budget,
        cache_prompt=cache_prompt,
        thinking=thinking,
    )


# -- text arm -----------------------------------------------------------------

def test_planner_returns_parsed_task_from_gemini_client():
    client = FakeChatClient(reply={"task": "run_command", "command": "id", "rationale": "whoami"})
    planner = _gemini_planner(client)

    task = planner.next_task("state summary here")

    assert task == {"task": "run_command", "command": "id", "rationale": "whoami"}
    # The Gemini default model and the state summary were forwarded to the client.
    (kwargs,) = client.calls
    assert kwargs["model"] == "gemini-2.5-flash"
    assert kwargs["response_format"] == {"type": "json_object"}  # text arm asks for a JSON object
    assert "tools" not in kwargs                                  # and sends no function schemas
    assert any("state summary here" in m["content"] for m in kwargs["messages"])


def test_planner_returns_none_on_client_error():
    client = FakeChatClient(error=RuntimeError("502 from gemini"))
    planner = _gemini_planner(client)

    assert planner.next_task("state") is None  # transport hiccup, not a crash


# -- schema arm ---------------------------------------------------------------

def test_schema_mode_forwards_tools_and_parses_function_call():
    client = FakeChatClient(tool_call={"name": "run_command", "arguments": {"command": "id", "rationale": "whoami"}})
    planner = _gemini_planner(client, mode="schema", tools=web_tools())

    task = planner.next_task("state summary here")

    # Same dict shape as the text arm — the ablation invariant the engine relies on.
    assert task == {"task": "run_command", "command": "id", "rationale": "whoami"}

    (kwargs,) = client.calls
    assert kwargs["tool_choice"] == "required"            # the model must pick a task
    assert "response_format" not in kwargs                # schema arm does not ask for JSON text
    names = [t["function"]["name"] for t in kwargs["tools"]]
    assert names == ["install_toolkit", "scan_network", "run_command", "done"]  # one function per task
    assert any("state summary here" in m["content"] for m in kwargs["messages"])


def test_schema_mode_returns_none_on_client_error():
    client = FakeChatClient(error=RuntimeError("502 from gemini"))
    planner = _gemini_planner(client, mode="schema", tools=web_tools())

    assert planner.next_task("state") is None  # same no-crash contract in schema mode


# -- reasoning budget ---------------------------------------------------------

def test_reasoning_budget_forwarded_to_gemini_extra_body():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})
    planner = _gemini_planner(client, reasoning_budget=0)  # 0 disables thinking

    planner.next_task("state")

    (kwargs,) = client.calls
    assert kwargs["extra_body"] == {
        "extra_body": {"google": {"thinking_config": {"thinking_budget": 0}}}
    }


def test_no_reasoning_budget_sends_no_extra_body():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})
    planner = _gemini_planner(client)  # default: unset

    planner.next_task("state")

    (kwargs,) = client.calls
    assert "extra_body" not in kwargs  # other backends never see the passthrough


# -- thinking toggle ----------------------------------------------------------

def test_thinking_disabled_sends_deepseek_switch():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})
    planner = _gemini_planner(client, thinking=False)

    planner.next_task("state")

    (kwargs,) = client.calls
    assert kwargs["extra_body"] == {"thinking": {"type": "disabled"}}


def test_thinking_enabled_sends_enabled_switch():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})
    planner = _gemini_planner(client, thinking=True)

    planner.next_task("state")

    (kwargs,) = client.calls
    assert kwargs["extra_body"] == {"thinking": {"type": "enabled"}}


def test_thinking_none_sends_no_switch():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})
    planner = _gemini_planner(client)  # thinking unset -> leave backend default alone

    planner.next_task("state")

    (kwargs,) = client.calls
    assert "extra_body" not in kwargs


# -- tolerant JSON parse (the "Extra data" failure) ---------------------------

def test_text_mode_tolerates_trailing_data_after_json():
    # deepseek-flash in thinking mode appended extra content after the object,
    # which crashed strict json.loads with "Extra data". raw_decode keeps the
    # first object and drops the trailing noise.
    noisy = '{"task": "scan_network", "rationale": "go"}\n\nHere is my reasoning...'
    client = FakeChatClient(reply={"ignored": True})
    # Override the canned content with the noisy string directly.
    client.chat.completions = type(
        "C", (), {"create": lambda _self, **kw: (client.calls.append(kw), FakeCompletion(noisy))[1]}
    )()
    planner = _gemini_planner(client)

    task = planner.next_task("state")

    assert task == {"task": "scan_network", "rationale": "go"}


# -- prompt caching / per-turn delta ------------------------------------------

def test_cache_prompt_sends_full_summary_then_only_delta():
    client = FakeChatClient(reply={"task": "scan_network", "rationale": "x"})
    planner = _gemini_planner(client, cache_prompt=True)

    planner.next_task("line A\nline B")
    planner.next_task("line A\nline C")  # B -> C is the only change

    first, second = client.calls
    # Turn 1 carries the full state; the system prompt is the stable prefix.
    assert "Current state:\nline A\nline B" in first["messages"][-1]["content"]
    assert first["messages"][0] == {"role": "system", "content": "SYS"}
    # Turn 2 sends only the changed line as the fresh user content...
    assert "line C" in second["messages"][-1]["content"]
    assert "line A" not in second["messages"][-1]["content"]
    assert "changes since your last turn" in second["messages"][-1]["content"].lower()
    # ...with turn 1 carried forward as the (cacheable) transcript prefix.
    assert second["messages"][0] == {"role": "system", "content": "SYS"}
    assert any(m["role"] == "assistant" for m in second["messages"][:-1])


def test_stateless_mode_resends_full_summary_each_turn():
    client = FakeChatClient(reply={"task": "scan_network", "rationale": "x"})
    planner = _gemini_planner(client)  # cache_prompt off (the baseline)

    planner.next_task("line A\nline B")
    planner.next_task("line A\nline C")

    for call in client.calls:
        # No carried transcript: every turn is system prompt + one full-state user msg.
        assert len(call["messages"]) == 2
        assert call["messages"][-1]["content"].startswith("Current state:")


# -- token accounting ---------------------------------------------------------

def test_token_usage_accumulates_across_turns():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"}, usage=_fake_usage(100, 20, cached=40))
    planner = _gemini_planner(client)

    planner.next_task("state")
    planner.next_task("state")

    assert planner.prompt_tokens == 200
    assert planner.completion_tokens == 40
    assert planner.cached_tokens == 80
    assert planner.total_tokens == 240


def test_missing_usage_leaves_counters_at_zero():
    client = FakeChatClient(reply={"task": "done", "rationale": "x"})  # no usage reported
    planner = _gemini_planner(client)

    planner.next_task("state")

    assert planner.total_tokens == 0  # a backend that omits usage must not crash
