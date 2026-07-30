"""Command-line entry point: ``sombra <agent> [options]``."""

from __future__ import annotations

import argparse
import sys

from .agents import AGENTS, run_agent
from .config import AgentConfig


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sombra", description="Blind autonomous LLM red-team harness")
    p.add_argument("agent", choices=sorted(AGENTS), help="which agent to run")
    p.add_argument("--backend", choices=("deepseek", "ollama"), default=None)
    p.add_argument("--api-key", default=None, help="hosted-backend key (else $DEEPSEEK_API_KEY)")
    p.add_argument("--model", default=None, help="override the backend default model")
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
        "max_turns": args.max_turns if args.max_turns is not None else spec.default_max_turns,
        "restore_on_exit": not args.no_restore,
    }
    config = AgentConfig.from_sources(cli={k: v for k, v in cli.items() if v is not None}, config_file=args.config)
    config = config.resolve_api_key(interactive=True)
    if config.uses_hosted_key() and not config.api_key:
        print("[!] No API key provided.", file=sys.stderr)
        return 2

    result = run_agent(args.agent, config)
    print(f"\n[*] {'SUCCESS' if result.success else 'no flag'} in {result.turns} turns. Audit: runs/{result.run_id}.jsonl")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
