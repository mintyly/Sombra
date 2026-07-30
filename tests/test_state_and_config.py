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
    assert AgentConfig(backend="deepseek").resolved_model() == "deepseek-chat"
    assert AgentConfig(backend="ollama").resolved_model() == "gemma3:12b"
    assert AgentConfig(backend="deepseek", model="custom").resolved_model() == "custom"
