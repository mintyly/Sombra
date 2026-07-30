# Migration: four monoliths → one tested package

## What changed structurally

The original four scripts (`cradle_agent.py`, `sombra_agent_dumb.py`, `sombra_agent.py`, `sombra_bwapp_agent.py`, ~2,500 lines total) were each self-contained and shared roughly 70% of their code by copy-paste: `host_exec`, `guest_bash`, `resolve_vm_names`, snapshot management, the `StateService`, `get_next_task`, and the main turn loop all appeared four times, and had drifted apart (e.g. the flag regex matched lowercase in some copies but not others; only one copy toggled the scan subnet both ways).

Everything shared now lives once in `src/sombra/`. Each agent is a small spec in `agents.py` (roles, state class, task registry, prompt). Behaviour was preserved — task names the planner emits (`run_command`, `test_winrm`, `scan_network`, `find_flag`, …) are unchanged, so existing prompts and any saved transcripts still line up. Result: 1,772 lines of source covering all four agents plus a shared core, and 286 lines of tests, versus 2,492 lines of duplicated script.

The one prototype behaviour deliberately *not* carried over: the emergency "if scan repeats 5×, force a toolkit install" hack in the WinRM loop. The wasted-turn cap and repeat counter in `engine.py` cover the same failure generally; special-casing one task name in the shared loop wasn't worth it. Everything else — the `-Pn` scan rationale, the base64 credential/`-EncodedCommand` shipping, the DNS-heal-then-verify dance, the command-history digest — is preserved with its original explanation.

## The headline change: denylist → allowlist

**Before.** `OUT_OF_SCOPE_IPS = {"192.168.56.1", "192.168.57.1"}` — a default-allow denylist. The agent could target anything; two gateway addresses were subtracted out. Anything not explicitly listed (a colleague's host on the same `/24`, any public IP via `curl`) was allowed.

**After.** `scope.Scope` is allowlist-first, default-deny:

1. `target_subnets` — the only networks the agent may scan or attack.
2. `deny` — hard never-touch addresses, refused even inside a target subnet (defence in depth).
3. `infra_allow` — loopback / attacker box / public DNS / `0.0.0.0`: referenceable in a command but never a target.

A target is in-scope only if it is inside a target subnet and not denied. Every free-form command is gated by `Scope.check_command`, which extracts each IPv4 literal and refuses the first that isn't referenceable — so an unrecognised public address is now denied by default. Refusals are written to the audit log.

Address matching uses `ipaddress` objects, never substring containment. The regex extracts whole dotted-quads with a digit-*and*-dot boundary on both sides, which fixes two bug classes at once: `192.168.56.1` is no longer "found" inside `192.168.56.178`, and `1.2.3.4` is no longer pulled out of a version string like `1.2.3.4.5`. Both are covered by tests in `tests/test_scope.py`.

## Other hardening

- **No secret in source.** `DEEPSEEK_API_KEY = ""` and the inline `input()` prompt are gone. `AgentConfig.from_sources` resolves CLI > env > file; the interactive prompt is opt-in and only fires from the CLI, so batch runs never block. `.gitignore` excludes keys and `runs/`.
- **Audit trail.** `audit.AuditLog` writes append-only JSONL per run — planner decisions, executed commands, scope refusals, flag capture. This is both the accountability record and the raw data for per-turn analysis.
- **Testable seams.** `parse_nmap` is pure; `Planner` and the DNS/apt helpers take injected clients/runners; the engine takes an injected planner and VBox. That's what lets the loop be tested with no range.

## For anyone extending this

Add an agent: append an `AgentSpec` to `AGENTS` and (if it needs new primitives) a task module under `tasks/`. Add a backend: one entry in `config.BACKENDS`. Change scope for a run: construct `Scope(target_subnets=..., deny=..., infra_allow=...)` and pass it into the config. Run `pytest` before pushing; CI will also run ruff and mypy.
