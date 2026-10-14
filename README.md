# Sombra
 
A blind LLM red-team harness, built for NUS Odyssey P01204, benchmarking how well LLM agents handle autonomous red-teaming. Showcased at STANDCON2026.

## Install
 
```bash
pip install -e ".[dev]"
```
 
Python 3.8+. Runtime deps (`openai`, `pywinrm`) are pinned in `pyproject.toml`.
 
## Run
 
```bash
export DEEPSEEK_API_KEY=sk-...     # dont leak your api key !
sombra bwapp                       # blind web agent, DeepSeek planner
sombra bwapp --model deepseek-v4-pro
sombra winrm --backend ollama      # local planner instead
sombra winrm --backend gemini      # needs GEMINI_API_KEY
sombra bwapp --cache               # cache the prompt, send only the per-turn delta
sombra winrm-guided --max-turns 30
```
 
## Tests
 
```bash
pytest     # 29 tests, no network, API key, or VirtualBox needed
```
 
The pure logic is tested directly, the turn loop runs end to end against a fake planner and fake VBox. 

CI is ruff, mypy, and pytest on 3.10–3.12. VM layer is tested on the live range, not in CI.