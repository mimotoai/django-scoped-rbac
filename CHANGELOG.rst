======================
scoped_rbac Change Log
======================

.. current developments

Unreleased
====================

**Fixed:**

* Security: updates (``PUT`` and ``PATCH``) through ``AccessControlledModelViewSet``
  are now authorized against the object as it was saved, including changes made by
  ``save()``, ``Serializer.update()``, signals and many-to-many fields. An update
  that changes an object's ``rbac_context`` (or ``rbac_contexts``) now requires the
  permission in a destination context as well as in the current one; for an object
  with several contexts, permission in any one of them suffices. A denied update is
  rolled back. Previously a ``PATCH`` could move an object, such as a
  ``RoleAssignment``, into a context where the user had no permission (#1).
* The user's grants are computed once per request (``policy_for`` caches them on
  the request), so an update to the user's own ``RoleAssignment`` cannot grant the
  permission that authorizes it.
* Creating or updating an object in the reserved ``__SOME_CONTEXT__`` context is
  rejected with 400 and rolled back.
* ``IsAuthorized`` now checks objects with multiple ``rbac_contexts`` against each
  of their contexts instead of failing; an object with no contexts is denied.
* ``PATCH`` on ``RoleViewSet`` no longer raises ``TypeError``.

**Note:** subclasses of ``AccessControlledModelViewSet`` that override
``perform_update`` or ``perform_create`` must call ``super()``, or these checks are
skipped. Side effects outside the database, such as signal handlers sending email,
may run before a denied update is rolled back.

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


