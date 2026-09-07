"""End-to-end loop test with everything external faked.

Proves the turn loop, task dispatch, scope refusal, flag capture, budget
accounting, and the no-turn-charged-for-a-planner-hiccup rule — all without a
network, an API key, or VirtualBox. That coverage is the whole payoff of pulling
the loop out of four copy-pasted ``main()`` functions.
"""

import json

from sombra.audit import AuditLog
from sombra.config import AgentConfig
from sombra.engine import Engine
from sombra.scope import Scope
from sombra.state import WebState
from sombra.tasks import TaskContext
from sombra.tasks import web as web_tasks


class FakePlanner:
    # The engine consumes a task *dict* and never sees how the planner produced
    # it. Both ablation arms (text-parsed and schema-constrained function calls)
    # converge on this same shape, so every engine test here is mode-invariant:
    # faking at this boundary covers both planner modes at once.
    def __init__(self, script):
        self.script = list(script)

    def next_task(self, _summary):
        return self.script.pop(0) if self.script else {"task": "done"}


class FakeVBox:
    """Records guest commands; returns a canned response per command."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.restored = False

    def ensure_snapshots(self, vms):
        pass

    def restore_snapshots(self, vms):
        self.restored = True

    def guest_bash(self, vm, command, timeout=30):
        self.calls.append(command)
        for needle, resp in self.responses.items():
            if needle in command:
                return resp
        return ""


def _ctx(vbox, tmp_path):
    cfg = AgentConfig(scope=Scope(target_subnets=("192.168.56.0/24",)), audit_dir=tmp_path)
    state = WebState(toolkit_installed=True)
    audit = AuditLog.create(tmp_path, "test")
    return TaskContext(state=state, vbox=vbox, config=cfg, vms={"attacker": "atk"}, audit=audit), audit


def test_flag_capture_ends_run(tmp_path):
    vbox = FakeVBox({"cat /var/flag": "FLAG{pwned-123}"})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner([{"task": "run_command", "command": "cat /var/flag", "rationale": "read it"}])
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    result = engine.run(max_turns=10)
    assert result.success and result.flag == "FLAG{pwned-123}"
    assert result.turns == 1
    assert vbox.restored  # snapshot restored in finally


def test_scope_refusal_blocks_out_of_scope_command(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)
    # 93.184.216.34 is a real public IP and NOT in infra_allow, so it must be refused.
    planner = FakePlanner([{"task": "run_command", "command": "curl http://93.184.216.34/x", "rationale": "x"}])
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    engine.run(max_turns=3)
    # the refused command must never have reached the guest
    assert not any("93.184.216.34" in c for c in vbox.calls)


def test_bwapp_agent_does_not_pin_security_level():
    # The security-level pin was removed. No agent carries scope hardening, so
    # the scope build_engine wires for bwapp is just the configured scope,
    # unchanged — and a security-level downgrade to low (0) is allowed.
    from sombra.agents import AGENTS

    assert not AGENTS["bwapp"].scope_hardening, "bwapp must no longer pin the security level"
    assert not AGENTS["winrm"].scope_hardening

    # build_engine only rewrites the scope when scope_hardening is non-empty; with
    # it empty the scope passes through, so the default scope's behaviour is what
    # a bwapp run gets. A downgrade command must sail through.
    scope = Scope(target_subnets=("192.168.56.0/24",))
    ok_low, _ = scope.check_command(
        "curl -d 'login=bee&password=bug&security_level=0&form=submit' http://192.168.56.178/bWAPP/login.php"
    )
    assert ok_low, "setting security_level=0 must no longer be refused"


def test_planner_hiccup_does_not_spend_budget(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)

    class FlakyPlanner:
        def __init__(self):
            self.n = 0

        def next_task(self, _s):
            self.n += 1
            if self.n <= 3:
                return None            # 3 transport hiccups
            return {"task": "done"}    # then a real decision

    engine = Engine(ctx, web_tasks.REGISTRY, FlakyPlanner(), ["atk"], audit)
    result = engine.run(max_turns=5)
    # only the real 'done' decision counts; the 3 Nones were free. Without the
    # hiccup-exemption this would be 4 turns (or the run would end early).
    assert result.turns == 1


def test_run_end_audit_line_records_tokens_and_turns_to_objective(tmp_path):
    vbox = FakeVBox({"cat /var/flag": "FLAG{pwned-123}"})
    ctx, audit = _ctx(vbox, tmp_path)

    class CountingPlanner(FakePlanner):
        total_tokens = 1234  # the engine reads this off the planner for the audit line

    planner = CountingPlanner([{"task": "run_command", "command": "cat /var/flag", "rationale": "read it"}])
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    result = engine.run(max_turns=10)
    assert result.tokens == 1234 and result.turns_to_objective == 1

    records = [json.loads(line) for line in audit.path.read_text().splitlines()]
    (run_end,) = [r for r in records if r["kind"] == "run_end"]
    assert run_end["tokens"] == 1234          # tokens-per-run, for comparing configs
    assert run_end["turns_to_objective"] == 1  # the flag landed on turn 1


def test_turns_to_objective_none_when_no_flag(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner([{"task": "done"}])  # gives up without a flag
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    result = engine.run(max_turns=5)
    assert not result.success and result.turns_to_objective is None


def test_unknown_task_skipped(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner([{"task": "nonexistent", "rationale": "?"}, {"task": "done"}])
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)
    result = engine.run(max_turns=5)
    assert not result.success  # nothing captured, but no crash


def test_successful_run_writes_markdown_report(tmp_path):
    vbox = FakeVBox({"cat /var/flag": "FLAG{pwned-123}"})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner(
        [{"task": "run_command", "command": "cat /var/flag", "rationale": "read the flag file"}]
    )
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    result = engine.run(max_turns=10)
    assert result.success

    report = audit.report_path
    assert report.exists() and report.suffix == ".md"
    text = report.read_text(encoding="utf-8")
    # The report is the human-readable twin of the JSONL: outcome, the turn, the
    # planner's rationale, and the command that actually ran all appear.
    assert "SUCCESS" in text
    assert "FLAG{pwned-123}" in text
    assert "read the flag file" in text           # planner rationale rendered
    assert "cat /var/flag" in text                # the executed command rendered
    assert "Turn 1" in text


def test_no_report_when_no_flag(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner([{"task": "done"}])  # gives up without a flag
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)

    result = engine.run(max_turns=5)
    assert not result.success
    # The vulnerability report is only meaningful when a vuln was exploited.
    assert not audit.report_path.exists()
