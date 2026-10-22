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
* The save and these checks run in a transaction on the model's write database
  (``router.db_for_write``), and the checks read a fresh instance from that
  database. Under a primary/replica router they no longer read a replica that
  cannot see the update, and a denied update to a model routed to a non-default
  database is rolled back there.
* Creating or updating an object in the reserved ``__SOME_CONTEXT__`` context is
  rejected with 400 and rolled back. Values equal to it after Unicode NFKC
  normalisation, case folding and stripping whitespace (e.g.
  ``__some_context__``) are rejected too, since a case- or accent-insensitive
  collation could treat them as the same context. The contexts checked include
  those reported by the ``contexts_for`` of the view's permission classes,
  including classes nested in DRF's composed permissions (``&``, ``|``, ``~``).
* ``IsAuthorized`` now checks objects with multiple ``rbac_contexts`` against each
  of their contexts instead of failing; an object with no contexts is denied.
* ``PATCH`` on ``RoleViewSet`` no longer raises ``TypeError``.

**Notes:**

* Subclasses of ``AccessControlledModelViewSet`` that override ``perform_update``
  or ``perform_create`` must call ``super()``, or these checks are skipped.
* Rolling back a denied update requires a transactional database backend; with
  e.g. MySQL's MyISAM the 403 is returned but the write remains.
* ``router.db_for_write`` for access-controlled models must not depend on mutable
  instance fields such as ``rbac_context``. Otherwise a save can be routed to a
  different database than the transaction and is not rolled back (#42).
* The pre-save object check runs outside the transaction, so a concurrent change
  between it and the save can be overwritten (#43).
* Side effects outside the database, such as signal handlers sending email, may run
  before a denied update is rolled back.
* Models whose ``rbac_contexts`` come from relations should query the instance's
  own database, e.g. ``self.tags.using(self._state.db)``. Otherwise a read router
  may answer them from a replica that does not see the update.
* An update whose instance ends up saved to a database other than its write
  database now fails with ``ImproperlyConfigured``, because it could be neither
  checked nor rolled back.

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


