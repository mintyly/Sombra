"""Command-line entry point: ``sombra <agent> [options]``."""

from __future__ import annotations

import argparse
import sys

from .agents import AGENTS, run_agent
from .config import BACKENDS, AgentConfig, known_models


def _model_help() -> str:
    """Advertise each backend's selectable models in the --model help."""
    parts = []
    for backend in sorted(BACKENDS):
        models = known_models(backend)
        if models:
            parts.append(f"{backend}: {models[0]} [default], " + ", ".join(models[1:]))
    listed = "; ".join(parts)
    return f"planner model to run (any id accepted; known — {listed})"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sombra", description="Blind autonomous LLM red-team harness")
    p.add_argument("agent", choices=sorted(AGENTS), help="which agent to run")
    p.add_argument("--backend", choices=sorted(BACKENDS), default=None)
    p.add_argument("--api-key", default=None, help="hosted-backend key (else $DEEPSEEK_API_KEY / $GEMINI_API_KEY)")
    p.add_argument("--model", default=None, help=_model_help())
    p.add_argument("--planner-mode", choices=("text", "schema"), default=None,
                   help="how the planner emits tasks: 'text' (parse JSON reply) or 'schema' (native function calling)")
    p.add_argument("--reasoning-budget", type=int, default=None,
                   help="Gemini thinking-token cap (0 disables thinking; omit for backend default)")
    p.add_argument("--cache", dest="cache_prompt", action="store_true", default=None,
                   help="cache the stable system prompt / range context and send only the per-turn state delta")
    # Two plain flags on one dest rather than argparse.BooleanOptionalAction,
    # which only exists on Python 3.9+ (the range host runs 3.8). Default None
    # (set below) = "leave the backend's default"; DeepSeek resolves that to off.
    p.add_argument("--thinking", dest="thinking", action="store_true", default=None,
                   help="force planner thinking mode ON (DeepSeek defaults it off for clean structured output)")
    p.add_argument("--no-thinking", dest="thinking", action="store_false",
                   help="force planner thinking mode OFF")
    p.set_defaults(thinking=None)
    p.add_argument("--max-turns", type=int, default=None)
    p.add_argument("--no-restore", action="store_true", help="leave the range dirty on exit")
    p.add_argument("--config", default=None, help="path to a JSON config file")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    spec = AGENTS[args.agent]

    cli = {
        "backend": args.backend,
        "api_key": args.api_key,
        "model": args.model,
        "planner_mode": args.planner_mode,
        "reasoning_budget": args.reasoning_budget,
        "cache_prompt": args.cache_prompt,
        "thinking": args.thinking,
        "max_turns": args.max_turns if args.max_turns is not None else spec.default_max_turns,
        "restore_on_exit": not args.no_restore,
    }
    config = AgentConfig.from_sources(cli={k: v for k, v in cli.items() if v is not None}, config_file=args.config)
    config = config.resolve_api_key(interactive=True)
    if config.uses_hosted_key() and not config.api_key:
        print("[!] No API key provided.", file=sys.stderr)
        return 2

    result = run_agent(args.agent, config)
    objective = result.turns_to_objective if result.turns_to_objective is not None else "-"
    print(
        f"\n[*] {'SUCCESS' if result.success else 'no flag'} in {result.turns} turns "
        f"(objective@{objective}, {result.tokens} tokens). Audit: runs/{result.run_id}.jsonl"
    )
    if result.success:
        print(f"[*] Vulnerability report: runs/{result.run_id}.md")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
