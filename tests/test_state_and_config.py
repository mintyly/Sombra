import json

from sombra.config import AgentConfig
from sombra.state import ScriptedState, WebState, WinRMState


def test_web_state_digest_shows_earlier_and_last():
    st = WebState()
    for i in range(3):
        st.command_history.append({"command": f"cmd{i}", "output": f"out{i}"})
    summary = st.summary()
    assert "Commands run so far: 3" in summary
    # earlier commands appear as digests; the most recent appears in full
    assert "cmd0" in summary and "cmd2" in summary
    assert 'do not re-run this to "check" it again' in summary


def test_web_state_empty():
    assert "No hosts discovered yet." in WebState().summary()


def test_winrm_state_reports_auth():
    st = WinRMState()
    st.discovered_hosts["192.168.56.50"] = {"open_ports": [5985], "os": "Windows"}
    st.winrm_sessions["192.168.56.50"] = True
    assert "WinRM authenticated" in st.summary()


def test_scripted_state_tracks_progress():
    st = ScriptedState()
    st.current_script_index = 2
    assert "Scripts executed: 2" in st.summary()


def test_config_precedence_cli_over_env_over_file(tmp_path):
    cfg_file = tmp_path / "c.json"
    cfg_file.write_text(json.dumps({"max_turns": 10, "backend": "ollama"}))
    env = {"DEEPSEEK_API_KEY": "sk-fromenv", "SOMBRA_BACKEND": "deepseek"}
    cfg = AgentConfig.from_sources(
        cli={"max_turns": 99},           # CLI wins
        env=env,                          # env sets key + backend
        config_file=cfg_file,             # file sets base
    )
    assert cfg.max_turns == 99            # cli beat file
    assert cfg.backend == "deepseek"      # env beat file
    assert cfg.api_key == "sk-fromenv"


def test_config_ignores_unknown_keys(tmp_path):
    cfg_file = tmp_path / "c.json"
    cfg_file.write_text(json.dumps({"nonsense_key": 1, "max_turns": 5}))
    cfg = AgentConfig.from_sources(config_file=cfg_file, env={})
    assert cfg.max_turns == 5


def test_resolve_api_key_non_interactive_leaves_blank():
    cfg = AgentConfig(backend="deepseek", api_key="")
    assert cfg.resolve_api_key(interactive=False).api_key == ""  # no prompt in batch mode


def test_resolve_api_key_ollama_needs_no_key():
    cfg = AgentConfig(backend="ollama", api_key="")
    assert cfg.resolve_api_key().api_key == "ollama"


def test_resolved_model_defaults():
    assert AgentConfig(backend="deepseek").resolved_model() == "deepseek-flash"
    assert AgentConfig(backend="ollama").resolved_model() == "gemma3:12b"
    assert AgentConfig(backend="deepseek", model="custom").resolved_model() == "custom"


def test_known_models_lists_deepseek_choices():
    from sombra.config import known_models

    models = known_models("deepseek")
    assert models[0] == "deepseek-flash"         # default is first (V4.1-Flash)
    assert "deepseek-v4-pro" in models           # the selectable alternative
    assert known_models("ollama") == []          # no pinned list -> empty


def test_deepseek_pro_selectable_via_model():
    # The "selector": pick a specific DeepSeek model with --model / config.
    assert AgentConfig(backend="deepseek", model="deepseek-v4-pro").resolved_model() == "deepseek-v4-pro"


def test_resolved_thinking_deepseek_defaults_off():
    # deepseek-flash ships thinking ON, which breaks structured/schema output;
    # so with no explicit choice the harness turns it off for DeepSeek.
    assert AgentConfig(backend="deepseek").resolved_thinking() is False
    # ...but other backends are left alone (None = don't send the switch).
    assert AgentConfig(backend="gemini").resolved_thinking() is None
    assert AgentConfig(backend="ollama").resolved_thinking() is None


def test_resolved_thinking_explicit_choice_wins():
    assert AgentConfig(backend="deepseek", thinking=True).resolved_thinking() is True
    assert AgentConfig(backend="gemini", thinking=False).resolved_thinking() is False


def test_gemini_backend_uses_openai_compatible_endpoint():
    cfg = AgentConfig(backend="gemini")
    assert cfg.base_url() == "https://generativelanguage.googleapis.com/v1beta/openai/"
    assert cfg.resolved_model() == "gemini-2.5-flash"
    assert cfg.uses_hosted_key()  # a key is required, like deepseek


def test_gemini_api_key_env_selects_gemini_backend():
    cfg = AgentConfig.from_sources(env={"GEMINI_API_KEY": "gkey-123"})
    assert cfg.backend == "gemini"   # defaulted from the env var
    assert cfg.api_key == "gkey-123"


def test_sombra_backend_env_overrides_key_default():
    # An explicit backend wins even when a key var would have defaulted otherwise.
    cfg = AgentConfig.from_sources(env={"GEMINI_API_KEY": "gkey-123", "SOMBRA_BACKEND": "ollama"})
    assert cfg.backend == "ollama"


def test_planner_mode_defaults_to_text():
    assert AgentConfig().planner_mode == "text"


def test_planner_mode_cli_beats_env():
    cfg = AgentConfig.from_sources(cli={"planner_mode": "schema"}, env={"SOMBRA_PLANNER_MODE": "text"})
    assert cfg.planner_mode == "schema"  # cli wins, as for every other field


def test_reasoning_budget_and_cache_default_off():
    cfg = AgentConfig()
    assert cfg.reasoning_budget is None  # backend default thinking
    assert cfg.cache_prompt is False     # baseline resends full state each turn


def test_reasoning_budget_and_cache_from_env():
    cfg = AgentConfig.from_sources(env={"SOMBRA_REASONING_BUDGET": "256", "SOMBRA_CACHE_PROMPT": "true"})
    assert cfg.reasoning_budget == 256   # parsed to int
    assert cfg.cache_prompt is True


def test_reasoning_budget_cli_beats_env():
    cfg = AgentConfig.from_sources(cli={"reasoning_budget": 0}, env={"SOMBRA_REASONING_BUDGET": "512"})
    assert cfg.reasoning_budget == 0     # cli wins, and 0 (disable thinking) is not treated as unset


def test_thinking_flags_parse_without_python39_action():
    # --thinking / --no-thinking must work on Python 3.8 (no BooleanOptionalAction).
    from sombra.cli import build_parser

    p = build_parser()
    assert p.parse_args(["bwapp"]).thinking is None            # unset -> backend default
    assert p.parse_args(["bwapp", "--thinking"]).thinking is True
    assert p.parse_args(["bwapp", "--no-thinking"]).thinking is False
