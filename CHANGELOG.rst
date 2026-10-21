======================
scoped_rbac Change Log
======================

.. current developments

v0.8.1
====================

Breaking release. The branch carries version 0.8.0; CI's publish job bumps the patch
version, so 0.8.1 is the first release published with these changes.

**Changed:**

* Requires Python 3.11+, Django 5.2+ and Django REST Framework 3.15+.
* Policy condition expressions are evaluated with Google's ``cel-expr-python``
  runtime instead of a vendored copy of ``cel-python``; the ``celpy`` and ``xlate``
  modules are no longer distributed.
* ``CEL_FUNCTIONS`` entries must have type-annotated parameters or be a
  ``cel.FunctionDecl``. Expressions that fail to evaluate deny access.
* ``Role.definition`` uses Django's ``models.JSONField``;
  ``django_jsonfield_backport`` is no longer required in ``INSTALLED_APPS``.
* ``django-rest-framework-condition`` and ``drf-extensions`` are no longer runtime
  dependencies.
* Packaging moved from Poetry to uv.
* Licensed under the MIT License (copyright David Charboneau, with portions
  copyright OpenTeams). Portions originally developed at Quansight remain under the
  BSD 3-Clause License with Quansight's copyright notice. Both are in a single
  ``LICENSE`` file, replacing ``LICENSE`` and ``LICENSE.txt``.

**Added:**

* ``scoped_rbac.cel`` with ``compile_expression``, ``is_true``,
  ``new_environment``, ``function_decl`` and ``InvalidExpression`` for evaluating
  CEL expressions.

**Fixed:**

* Removed a stray ``breakpoint()`` hit when a ``RootPolicy`` was configured as a
  default policy.


v0.0.2
====================



v0.0.1
====================


