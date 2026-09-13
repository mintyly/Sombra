# Sombra

A blind autonomous LLM red-team harness. An LLM *planner* emits structured tasks; deterministic Python *task-agents* execute them against an isolated cyber range; a shared turn loop drives the two with a stateless planner and an evidence-anchored state summary. Built for NUS Odyssey project P01204 (benchmarking LLM agents on autonomous red-teaming).

This is the packaged, tested rewrite of the original four prototype scripts. It keeps every behaviour that mattered and adds a shared core, an allowlist scope model, an audit trail, and a test suite.

## The autonomy spectrum

The point of the project is one variable — *how much does the agent get told?* — held against a fixed executor. Four agents span the range:

| Agent (`sombra <name>`) | Autonomy | What the planner is given |
|---|---|---|
| `scripted` | lowest | Orders a fixed 5-step APT32-A chain; deterministic agents run each step. The LLM only picks order. |
| `winrm-guided` | baseline | Blind primitives, but the prompt discloses the target (WinRM 5985), the creds (`vagrant:vagrant`), and a step plan. |
| `winrm` | high | Blind. Vulnerability-*named* primitives (`test_winrm`, `execute_powershell`, `find_flag`), but no disclosed target, ports, or creds. |
| `bwapp` | highest | Blind. One generic `run_command` shell — must find and chain a real web vulnerability itself to reach a flag outside the web root. |

`winrm` vs `winrm-guided` is a clean ablation (identical executor and primitives, prompt is the only difference).

## Install

```bash
pip install -e ".[dev]"     # editable, with pytest/ruff/mypy
```

Requires Python ≥ 3.8 (verified against earthquake's actual interpreters via `ast.parse(feature_version=...)` — every
module defers its annotations with `from __future__ import annotations`, so the `X | Y` syntax used throughout never
needs the 3.10 runtime it looks like it does). Runtime deps (`openai`, `pywinrm`) are pinned in `pyproject.toml`.

## Run

```bash
export DEEPSEEK_API_KEY=sk-...        # never hardcoded; env > file, CLI overrides both
sombra bwapp                          # blind web agent, DeepSeek planner
sombra bwapp --model deepseek-v4-pro   # pick the DeepSeek model (flash [default] | v4-pro)
sombra bwapp --thinking                # opt DeepSeek back into thinking mode (off by default)
sombra winrm --backend ollama         # local Ollama planner instead
export GEMINI_API_KEY=...             # or Gemini (OpenAI-compatible endpoint)
sombra winrm --backend gemini         # Gemini planner
sombra bwapp --backend gemini --reasoning-budget 0   # cap Gemini thinking tokens (0 = off)
sombra bwapp --cache                  # cache the stable prompt; send only the per-turn state delta
sombra winrm-guided --max-turns 30
sombra scripted --no-restore          # leave the range dirty for inspection
```

On start you pick which running VM is which (attacker / victim / router). Every run writes an append-only JSONL audit trail to `runs/<agent>-<timestamp>.jsonl` — one line per planner decision and executed command. The `run_end` line also carries `tokens` (tokens-per-run) and `turns_to_objective`, so a batch of trials under different `--reasoning-budget` / `--cache` settings is comparable straight from the JSONL.

A run that captures the flag additionally gets a human-readable **vulnerability report** at `runs/<agent>-<timestamp>.md`, rendered from the very same event stream: outcome, the exact planner model (backend + model id + emit mode), and token cost up top, then one section per turn — the task the planner chose, its rationale, the command that actually ran, and what came back (scope refusals included). The JSONL is for machines; the `.md` is the step-by-step narrative a human reads, and because both derive from one event list they cannot disagree about what happened. Range provisioning, flag-planting, and the VirtualBox DNS fix are in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

DeepSeek's current flagship (`deepseek-flash`, V4.1) ships with **thinking mode on**, which leaks non-JSON prose into text-mode replies (`Extra data` parse errors) and makes the API reject schema mode's forced tool choice. The harness therefore turns thinking **off** for DeepSeek by default so both planner modes produce clean structured output; pass `--thinking` to opt back in for an ablation (text mode stays robust either way — the parser keeps only the first JSON object and drops trailing noise). Other backends are left at their own defaults.

## Scope enforcement (allowlist, default-deny)

The security review flagged the original denylist (`OUT_OF_SCOPE_IPS`, default-allow). It is now an **allowlist**: a target is in-scope only if it is inside a declared `target_subnets` entry and not on the hard `deny` list. An address nobody thought to blacklist — a neighbour on the same `/24`, an arbitrary public host reached with `curl` — is refused by default. Loopback, the attacker box, and the DNS resolvers the installer needs are a separate `infra_allow` set: referenceable, but never treated as targets. Every free-form `run_command` is gated through `Scope.check_command` before it reaches the guest, and refusals are audit-logged. See [`docs/MIGRATION.md`](docs/MIGRATION.md).

## Architecture

```
cli → agents.AGENTS[name] (spec) → build_engine
                                     ├─ Planner        (llm, injectable client)
                                     ├─ TaskContext    (state, vbox, config, scope, audit)
                                     ├─ tasks.REGISTRY (web | winrm | scripted)
                                     └─ Engine.run()   (the one shared turn loop)
```

- `scope.py` — allowlist policy (the safety core).
- `state.py` — `BaseState` + per-agent summaries; the web state carries the anti-hallucination command digest.
- `net.py` — pure `parse_nmap`, plus DNS-heal / apt-lock helpers with an injected runner.
- `vbox.py` — all `VBoxManage` interaction, behind one class.
- `engine.py` — plan → execute → update loop, repeat counting, wasted-turn cap, snapshot restore in `finally`.
- `tasks/` — the deterministic task-agents, grouped by target.
- `prompts.py` — the four system prompts (the autonomy variable, isolated).

Adding a fifth agent is a spec entry in `agents.py`, not another monolith.

## Tests

```bash
pytest            # 29 tests, no network / API key / VirtualBox needed
```

The pure logic (scope, flag detection, nmap parsing, state summaries, config precedence) is unit-tested directly. The turn loop is tested end-to-end with a fake planner and fake VBox — flag capture, scope refusal, budget accounting, unknown-task handling. CI runs ruff + mypy + pytest on Python 3.10–3.12. The VM-touching layer is structured and mockable but is integration-tested on `earthquake` against the live range, not in CI.

## Layout

```
src/sombra/      core + tasks/ + agents + cli
tests/           unit + engine tests
docs/            OPERATIONS.md (range setup) · MIGRATION.md (refactor notes)
```

Author: June Ong · june@june.ong · github.com/mintyly · MIT.
