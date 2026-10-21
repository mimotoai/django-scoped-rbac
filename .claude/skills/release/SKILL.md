---
name: release
description: Prepare a django-scoped-rbac release — choose the version bump, update CHANGELOG.rst, and understand how GitLab CI publishes to PyPI. Use when asked to release, bump the version, or publish.
---

# Releasing

Publishing is done by GitLab CI, not locally. Never run `uv publish` yourself.

## What CI does

On every push to the default branch that changes `src/**`, the `publish` job in
`.gitlab-ci.yml`:

1. runs `uv version --bump patch`,
2. `uv build` and `uv publish` (token from the `POETRY_PYPI_ACCESS_TOKEN` CI variable),
3. commits `pyproject.toml` + `uv.lock` as `[ci skip] updated to X.Y.Z` and pushes.

So a merge that touches `src/` *is* a patch release.

## Preparing a release in a merge request

1. Decide the bump. Patch is automatic. For a breaking change (e.g. a renamed
   `scoped_rbac.cel` function, a new `SCOPED_RBAC` requirement, a dropped Python or
   Django version) bump minor in the MR so CI's patch bump lands on `X.(Y+1).1`:
   `uv version --bump minor` (this also updates `uv.lock`).
2. Move the `Unreleased` section of `CHANGELOG.rst` under the new version heading.
3. Verify: `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`,
   `uv lock --check`, and `uv build` (inspect `dist/` contents, then delete `dist/`).
4. Commit and open the MR. Ask before pushing.

## Downstream

`scrud-django` consumes this package (and the public `scoped_rbac.cel` API). Call out
any change to `compile_expression`, `is_true`, `new_environment`, `function_decl` or
`InvalidExpression` in the changelog under **Changed**.
