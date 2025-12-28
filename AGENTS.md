AGENTS.md - Agent Guidelines

Build / Test / Lint:
- Install deps: `python -m pip install -r requirements.txt` or activate the project venv
- Run all tests: `pytest -q` or `pytest -q src/test`
- Single test file: `pytest -q src/test/test_smtp.py`; single test: `pytest -q src/test/test_smtp.py::test_connect_timeout`
- Run by keyword: `pytest -q -k <expr>` (e.g. `-k connect_timeout`)
- Lint: `flake8 src --max-line-length=88`
- Format: `black .` and `isort .`; check-only: `black --check .`

Code Style:
- Formatting: use `black` and `isort`; target 88 char line length.
- Imports: group stdlib, third-party, local; use absolute imports; keep imports at top of module.
- Typing: add type hints for public functions/classes; prefer Python 3.10+ syntax for annotations.
- Naming: `snake_case` for functions/variables, `PascalCase` for classes, `CONSTANTS_UPPER` for constants.
- Error handling: avoid bare `except:`; catch specific exceptions, log and re-raise when appropriate.
- Logging: use `src.managers.log.get_logger()` or a module-level logger; avoid `print()` in production code.
- Tests: mock external network/DB calls; prefer small, non-destructive changes and run affected tests locally.

Cursor / Copilot:
- No `.cursor`/`.cursorrules` or `.github/copilot-instructions.md` detected; if present, follow those rules and prefer non-interactive guidance as advisory.

Need help? I can add CI examples, a `config.example`, or scaffold pre-commit hooks (black/isort/flake8).
