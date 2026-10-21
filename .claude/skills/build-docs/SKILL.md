---
name: build-docs
description: Build or preview the django-scoped-rbac Sphinx documentation. Use when editing docs/*.rst or docstrings and you need to check they render, or when asked to build/serve the docs.
---

# Building the docs

The docs dependencies live in the `docs` dependency group.

```shell
uv run --group docs make -C docs html      # output: build/sphinx/html/index.html
uv run --group docs make -C docs livehtml  # sphinx-autobuild with live reload
```

- `docs/Makefile` runs `sphinx-apidoc` into `docs/api/` (gitignored) before building.
- `docs/conf.py` calls `django.setup()` with `examples/scoped_rbac_example/settings.py`,
  so every app in that example's `INSTALLED_APPS` must be importable — add new ones
  to the dev dependency group.
- The build already emits ~90 warnings from existing content (untitled documents in
  the toctree, undefined labels). When changing docs, compare the warning count
  before and after rather than expecting zero; report only new warnings.
- Docstrings use reStructuredText: `.. code-block:: python`, double-backtick literals.
- CI publishes `build/sphinx/html` to GitLab Pages from the default branch
  (`pages` job in `.gitlab-ci.yml`).
