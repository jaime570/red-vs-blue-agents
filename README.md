# Red Team vs Blue Team: Multi-Agent Code Security Duel

Two Claude-powered agents compete round by round to harden a piece of code:

- 🔴 **Red agent (ethical pentester)** audits the code and returns a structured vulnerability report: severity, OWASP category, location, attack vector and recommendation.
- 🔵 **Blue agent (defender)** receives the report and patches the code, explaining every change.
- ⚖️ **Orchestrator** repeats Red → Blue, scores each round by severity and picks a winner:
  - **Blue wins** when Red can no longer find any CRITICAL or HIGH issues.
  - **Red wins** if the round limit is reached with blocking issues still open.

> This is **defensive** security. The red agent audits *your own* code so the blue agent can fix it. It writes reports and fixes, never working exploits or malware.

## Two implementations, one idea

The project implements the same duel twice to compare two ways of building agents:

| | `duelo_seguridad.py` | `duelo_seguridad_sdk.py` |
|---|---|---|
| Approach | Raw Anthropic Python SDK (Messages API) | Claude Agent SDK |
| How agents work | Pure text in, JSON out | Agents **use tools**: read files, grep, run Bash and `bandit` (SAST), edit files in place |
| Blue's output | Full patched code inside JSON | Edits the files directly, can run tests |
| Scope | One file or the built-in demo | A file or a whole folder (worked on a copy in `_work_duelo/`) |
| Extras | Saves the hardened code to a file | Final cleanup pass for remaining MEDIUM/LOW issues, JSON reports per round |

Building the raw version first made the agent loop explicit: prompting, structured output, parsing and orchestration are all hand-written. The Agent SDK version shows how much changes once agents can act on a real codebase.

## Example run

On the built-in demo (a small Flask app with SQL injection, path traversal, a hardcoded secret and debug mode on), the red agent's score dropped each round until the blue agent won:

| Round | Red's findings | Score |
|---|---|---|
| 1 | 2 critical, 2 high, 2 medium, 1 low | 39 pts |
| 2 | 1 high, 2 medium, 3 low | 15 pts |
| 3 | 1 medium, 4 low → **Blue wins** | 7 pts |

Scoring: critical = 10, high = 6, medium = 3, low = 1.

The fixes the blue agent applied include parameterized SQL queries, salted password hashing, CSRF protection, login rate limiting, a constant-time login check to prevent user enumeration, hardened session cookies, secrets loaded from environment variables, and safe path handling.

See [`examples/`](examples/) for the before/after code and the full JSON reports for every round:

- [`examples/app_vulnerable.py`](examples/app_vulnerable.py): starting code
- [`examples/app_hardened.py`](examples/app_hardened.py): code after the duel
- [`examples/informes/`](examples/informes/): red and blue reports per round

## Getting started

```bash
git clone https://github.com/jaime570/red-vs-blue-agents.git
cd red-vs-blue-agents
pip install -r requirements.txt
```

### Version 1: raw API

Copy `.env.example` to `.env` and add your Anthropic API key:

```
ANTHROPIC_API_KEY=your-api-key-here
```

```bash
python duelo_seguridad.py                          # run the built-in demo
python duelo_seguridad.py my_app.py --rondas 3     # audit your own file
python duelo_seguridad.py my_app.py --salida safe_app.py
```

The hardened code is saved as `<file>_endurecido.<ext>` unless you pass `--salida`.

### Version 2: Agent SDK

Requires the Claude Code CLI (`npm install -g @anthropic-ai/claude-code`). Log in with `claude` → `/login`.

```bash
python duelo_seguridad_sdk.py                       # run the built-in demo
python duelo_seguridad_sdk.py my_project/ --rondas 3
python duelo_seguridad_sdk.py my_app.py --sin-limpieza   # skip the final cleanup pass
```

The hardened code and the per-round reports are written to `_work_duelo/`. Your original files are never modified.

> ⚠️ **Security note:** to run unattended, the SDK agents use `permission_mode="bypassPermissions"` and have Bash access. They work on a copy of your code, but commands run on your machine. Only point it at code you trust.

## Design notes

- **Structured output:** both agents must answer with a fixed JSON schema. A tolerant parser extracts the JSON even if the model adds text or code fences.
- **Severity normalization:** "Crítica", "CRITICA" and "CRÍTICA" are treated as the same value (accents stripped, uppercased), so scoring doesn't depend on how the model spells it.
- **Failing safely:** if the red agent returns an invalid report, the orchestrator retries once and then **stops without declaring a winner**. An unreadable report never counts as "no vulnerabilities found".
- **Avoiding endless loops:** the red agent almost always finds something minor. Blocking issues decide the winner, and the SDK version applies one final cleanup pass for MEDIUM/LOW findings without re-auditing.
- **Dynamic token budget:** in the raw version, the blue agent's `max_tokens` scales with the size of the code and report, and truncated responses are flagged.

## Project structure

```
├── duelo_seguridad.py       # Version 1: raw Anthropic API
├── duelo_seguridad_sdk.py   # Version 2: Claude Agent SDK (tool-using agents)
├── comun.py                 # Shared code: scoring, severity handling, JSON parsing, console output
├── examples/                # Demo run: vulnerable vs hardened code + reports
├── requirements.txt
└── .env.example
```

## Tech stack

Python · Anthropic API · Claude Agent SDK · Bandit (SAST) · asyncio · OWASP Top 10

## Author

**Jaime Llorca Martínez**: Data Science Master's student, Madrid · [GitHub](https://github.com/jaime570)
