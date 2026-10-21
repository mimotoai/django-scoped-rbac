---
name: run-tests
description: Run django-scoped-rbac's tests — the full suite, a single module/test, or the lint and migration checks — and interpret safetydance BDD test failures. Use when verifying a change, debugging a failing test, or before committing.
---

# Running the tests

All commands run from the repo root; `uv run` syncs `.venv` from `uv.lock` first.

| Goal | Command |
|---|---|
| Full suite + coverage | `uv run pytest` |
| Fast, no coverage | `uv run pytest -q --no-cov -p no:warnings` |
| One module | `uv run pytest --no-cov tests/test_policy.py` |
| One test | `uv run pytest --no-cov "tests/test_rest.py::test_put_permissions"` |
| By keyword | `uv run pytest --no-cov -k cel` |
| Lint + format check | `uv run ruff check && uv run ruff format --check` |
| Pending migrations | `uv run pytest --no-cov tests/test_migrations.py` |

Before claiming work is done, run the full suite and the lint check, and report the
actual pass/fail counts.

## How the test environment is wired

- Django settings come from `tests/conftest.py::pytest_configure`, which calls
  `settings.configure(...)` — there is no settings module. Add test-only apps or
  `SCOPED_RBAC` options there.
- `scoped_rbac.conf` caches resolved settings (and the CEL environment) in the
  module-global `RESOLVED_SETTINGS`. A test that changes `SCOPED_RBAC` must build its
  own `conf.Settings(...)` (see `tests/test_load_settings.py`) or reset that global.
- `tests/test_rest.py`, `tests/test_multiple_contexts.py`, `tests/steps.py` and
  `tests/step_extensions.py` use **safetydance** scripted tests (`@scripted_test`,
  `Given/When/Then`). Inside `@step` functions, names such as `http_response` and
  `http_client` are injected by rewriting the function's AST — they look undefined
  but are not. This needs the `python38` branch of safetydance pinned in
  `pyproject.toml`; do not upgrade safetydance, safetydance-django or
  safetydance-test independently.

## Interpreting failures

- `ModuleNotFoundError: pkg_resources` → setuptools ≥81 got installed; the dev group
  pins `setuptools<81` for safetydance. Re-run `uv sync`.
- A failure deep inside `safetydance/_safetydance.py` usually means a `step_data`
  initializer has the wrong signature — initializers are called with the step
  context, e.g. `step_data(Faker, initializer=lambda context: Faker())`.
- A CEL condition evaluating to `False` unexpectedly: evaluation errors fail closed.
  Reproduce with `scoped_rbac.cel.compile_expression` and inspect
  `compiled.eval(data=...)` directly to see the `ERROR` value.
- Python 3.14 is not supported by the safetydance branch (`ast.NameConstant`).
