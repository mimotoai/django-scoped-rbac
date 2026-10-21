# django-scoped-rbac

Django / DRF app for role-based access control where roles are assigned *within* an
access-control context (e.g. "editor in project A"), with optional CEL conditions on
permissions. Import package: `scoped_rbac` (in `src/`). Python ≥3.11, Django 5.2 LTS.

## Commands

```shell
uv sync                                   # .venv with dev deps (default group)
uv run pytest                             # tests + coverage
uv run pytest --no-cov "tests/test_rest.py::test_put_permissions"
uv run ruff check && uv run ruff format --check
uv run --group docs make -C docs html     # docs → build/sphinx/html
uv lock                                   # after any pyproject.toml dependency change
```

Project skills: `run-tests`, `build-docs`, `release` (in `.claude/skills/`).
A PostToolUse hook ruff-formats Python files after each edit.

## Architecture

- `policy.py` — the policy algebra. JSON role definitions are parsed by
  `policy_from_json` into `PolicySet` / `PolicyDict` / `Expression` (CEL) /
  `Operator` / `ExpressionList` / `CompoundPolicy`; `sum_with` merges policies.
  `RootPolicy.should_allow(permission, context_id, resource)` is the entry point;
  lookups are nested `context → action IRI → resource type IRI`.
- `permissions.py` — `policy_for(request)` builds a user's `RootPolicy` from the
  settings defaults plus their `RoleAssignment`s; `IsAuthorized` is the DRF
  permission class. Every grant is also added under `SOME_CONTEXT` so "allowed in
  any context" checks (list/create) work.
- `filters.py` — `RbacFilter` restricts querysets to `rbac_context__in` the user's
  contexts.
- `conf.py` — lazy resolution of the `SCOPED_RBAC` setting (dict, dotted path,
  callable, or list of these, merged). Cached in the global `RESOLVED_SETTINGS`.
- `cel.py` — **public API** over Google's `cel-expr-python`: `compile_expression`,
  `is_true`, `new_environment`, `function_decl`, `InvalidExpression`. Used by
  `policy.Expression` and by the downstream `scrud-django` project — keep these
  names and signatures stable, and note any change in `CHANGELOG.rst`.
- `models.py` — `AccessControlledModel` (abstract, has `rbac_context`), `Role`
  (JSON `definition`), `RoleAssignment`. `rest.py`/`urls.py` expose them via DRF.

## CEL semantics (non-obvious)

- Expressions compile with `disable_check=True`: each top-level key of the resource
  mapping (or of `resource.to_cel()`) is a CEL variable.
- Any evaluation error or non-`bool` result **denies** (`is_true` returns `False`).
- cel-cpp dispatches functions on concrete argument types; a `DYN` parameter never
  matches. Hence `CEL_FUNCTIONS` entries need annotated params
  (`bool/int/float/str/bytes/dict/list`) or an explicit `cel.FunctionDecl`.
- Function names must not shadow CEL builtins (`int`, `double`, `string`, ...).

## Testing gotchas

- Test Django settings live in `tests/conftest.py::pytest_configure`, not a module.
- REST tests use safetydance scripted steps; names like `http_response` inside
  `@step` functions are injected by AST rewriting. This requires the safetydance
  `python38` git branch with `safetydance-django==0.0.6` / `safetydance-test==0.1.4`
  and `setuptools<81` — upgrade those together or not at all. No Python 3.14 yet.
- `tests/test_migrations.py` fails if a model change lacks a migration; generate
  one with a settings module that includes `scoped_rbac` (e.g. the example project
  in `examples/`).

## Conventions

- ruff, line length 88, `quote-style = "preserve"` — don't churn quotes.
- Migrations are excluded from ruff; never reformat existing migrations.
- Run tests and lint before claiming a change works; report real results.

## Known issues (pre-existing, not yet fixed)

- `authentication.py::ConditionalAnonymousAuthentication` references undefined
  names and cannot run; it is unused.
- `IsAuthorized.contexts_for` returns `None` when the object has `rbac_contexts`,
  and `has_object_permission` checks `obj.rbac_context` instead of the loop's
  `context`. Changing either alters authorization behaviour — confirm intent first.
- Root `manage.py` points at a nonexistent `scoped_rbac.settings`; use
  `examples/manage.py`.
- `LICENSE` (BSD-3, Quansight) and `LICENSE.txt` (MIT) disagree; metadata says MIT.
