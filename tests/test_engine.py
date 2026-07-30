"""End-to-end loop test with everything external faked.

Proves the turn loop, task dispatch, scope refusal, flag capture, budget
accounting, and the no-turn-charged-for-a-planner-hiccup rule — all without a
network, an API key, or VirtualBox. That coverage is the whole payoff of pulling
the loop out of four copy-pasted ``main()`` functions.
"""

from sombra.audit import AuditLog
from sombra.config import AgentConfig
from sombra.engine import Engine
from sombra.scope import Scope
from sombra.state import WebState
from sombra.tasks import TaskContext
from sombra.tasks import web as web_tasks


class FakePlanner:
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


def test_unknown_task_skipped(tmp_path):
    vbox = FakeVBox({})
    ctx, audit = _ctx(vbox, tmp_path)
    planner = FakePlanner([{"task": "nonexistent", "rationale": "?"}, {"task": "done"}])
    engine = Engine(ctx, web_tasks.REGISTRY, planner, ["atk"], audit)
    result = engine.run(max_turns=5)
    assert not result.success  # nothing captured, but no crash
