"""Human-readable vulnerability report, rendered from the audit event stream.

The JSONL trail (:mod:`sombra.audit`) is the machine record — one line per
decision and command, ideal for batch analysis but unpleasant to read. This
module turns the *same* list of records into a Markdown narrative: a header with
the outcome and cost, then one section per turn explaining what the planner
decided, why (its rationale), what command actually ran, and what came back.

It reads only the event dicts, so it stays in lockstep with the audit trail by
construction — there is no second source of truth to drift. A run that reached no
flag still renders (the engine simply does not ask for one); the header says so.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Sequence

# Event kinds that are per-turn *actions* (vs. the run-level book-ends). Order of
# appearance in the stream is the order they ran, so we attach each to the most
# recent planner_task turn.
_ACTION_KINDS = {"run_command", "execute_powershell", "test_winrm", "execute_script", "scope_refusal"}


def _fmt_ts(ts: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return "unknown"


def _code_block(text: str, lang: str = "") -> list[str]:
    body = (text or "").rstrip("\n")
    if not body:
        body = "(no output)"
    return [f"```{lang}", body, "```"]


def _render_action(rec: Mapping[str, Any]) -> list[str]:
    """One action event -> human-readable Markdown lines."""
    kind = rec.get("kind")

    if kind == "scope_refusal":
        return [
            "**Action:** `run_command` — **BLOCKED by scope policy**",
            "",
            f"Command refused before it reached the guest: `{rec.get('command', '')}`",
            "",
            f"Reason: {rec.get('reason', 'out of scope')}",
        ]

    if kind == "run_command":
        lines = ["**Action:** ran a shell command on the attacker box.", "", "Command:"]
        lines += _code_block(rec.get("command", ""), "bash")
        lines += ["", "Output:"]
        lines += _code_block(rec.get("output", ""))
        return lines

    if kind == "execute_powershell":
        lines = [
            f"**Action:** executed PowerShell on the victim (`{rec.get('target', '?')}`).",
            "",
            "Command:",
        ]
        lines += _code_block(rec.get("command", ""), "powershell")
        return lines

    if kind == "test_winrm":
        outcome = "SUCCESS" if rec.get("success") else "FAILED"
        return [
            f"**Action:** tested WinRM authentication against `{rec.get('target', '?')}` "
            f"as `{rec.get('username', '?')}` — **{outcome}**.",
        ]

    if kind == "execute_script":
        return [f"**Action:** executed scripted step `{rec.get('script', '?')}`."]

    return [f"**Action:** {kind}"]


def _header(records: Sequence[Mapping[str, Any]]) -> list[str]:
    start = next((r for r in records if r.get("kind") == "run_start"), {})
    end = next((r for r in records if r.get("kind") == "run_end"), {})
    captured = next((r for r in records if r.get("kind") == "flag_captured"), None)

    run_id = next((r.get("run_id") for r in records if r.get("run_id")), "unknown")
    agent = str(run_id).rsplit("-", 2)[0] if run_id != "unknown" else "unknown"
    success = bool(end.get("success"))
    flag = (captured or {}).get("flag") or end.get("flag")

    if success:
        obj = end.get("turns_to_objective")
        outcome = "**SUCCESS** — flag captured" + (f" on turn {obj}" if obj else "")
    else:
        outcome = "**no flag captured**"

    lines = [
        f"# Vulnerability report — `{agent}`",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Generated:** {_fmt_ts(time.time())}",
        f"- **Outcome:** {outcome}",
    ]
    model = start.get("model")
    if model:
        backend = start.get("backend")
        mode = start.get("planner_mode")
        thinking = start.get("thinking")
        think_str = None if thinking is None else ("thinking" if thinking else "non-thinking")
        extra = ", ".join(
            x for x in (backend and f"backend {backend}", mode and f"{mode} mode", think_str) if x
        )
        lines.append(f"- **Planner model:** `{model}`" + (f" ({extra})" if extra else ""))
    if flag:
        lines.append(f"- **Flag:** `{flag}`")
    lines += [
        f"- **Turns taken:** {end.get('turns', '?')}"
        + (f" / {start['max_turns']}" if start.get("max_turns") is not None else ""),
    ]
    tokens = end.get("tokens")
    if tokens is not None:
        detail = (
            f" (prompt {end.get('prompt_tokens', 0)}, "
            f"completion {end.get('completion_tokens', 0)}, "
            f"cached {end.get('cached_tokens', 0)})"
        )
        lines.append(f"- **Planner tokens:** {tokens}{detail}")
    lines += [
        "",
        "> Generated from the run's audit trail. The machine-readable event log "
        f"is the companion `{run_id}.jsonl` in the same directory.",
    ]
    return lines


def render_report(records: Sequence[Mapping[str, Any]]) -> str:
    """Render a full list of audit event dicts to a Markdown report string."""
    lines = _header(records)
    lines += ["", "## Attack timeline", ""]

    # Walk the stream; a planner_task opens a turn, following action events belong
    # to it until the next planner_task. Actions before any planner_task (there
    # should be none) are tolerated under a "Setup" heading.
    current_turn: dict | None = None
    saw_turn = False

    def flush_blank() -> None:
        if lines and lines[-1] != "":
            lines.append("")

    for rec in records:
        kind = rec.get("kind")
        if kind == "planner_task":
            saw_turn = True
            current_turn = dict(rec)
            turn_no = rec.get("turn", "?")
            name = rec.get("task", "?")
            repeats = rec.get("repeats") or 0
            suffix = f" (repeat x{repeats + 1})" if repeats else ""
            flush_blank()
            lines.append(f"### Turn {turn_no} — `{name}`{suffix}")
            rationale = rec.get("rationale")
            if rationale:
                lines += ["", f"**Planner rationale:** {rationale}"]
            lines.append("")
        elif kind in _ACTION_KINDS:
            if not saw_turn:
                lines += ["### Setup", ""]
                saw_turn = True
            lines += _render_action(rec)
            lines.append("")
        elif kind == "flag_captured":
            flush_blank()
            lines += [
                f"### Flag captured (turn {rec.get('turn', '?')})",
                "",
                f"`{rec.get('flag', '')}`",
                "",
            ]

    if not saw_turn:
        lines += ["_No planner turns were recorded for this run._", ""]

    lines += [
        "## Reproduction",
        "",
        "Replay the full machine-readable decision-and-command stream from the "
        "companion JSONL trail; each `run_command` / `execute_powershell` line is "
        "the exact action issued, in order.",
        "",
    ]
    return "\n".join(lines).rstrip("\n") + "\n"
