======================
scoped_rbac Change Log
======================

.. current developments

v0.9.2
====================

**Fixed:**

* Merging roles whose grants combine conditional and unconditional permissions no
  longer raises, and merge results no longer depend on the order roles are combined
  (#2, #3).
* Merging policies of a type ``sum_with`` cannot combine raises
  ``NotImplementedError`` instead of returning ``None``.

v0.9.1
====================

Security and authorization-behaviour release. The branch carries version 0.9.0; CI's
publish job bumps the patch version, so 0.9.1 is the first release published with
these changes.

**Fixed:**

* Security: an update (``PUT``/``PATCH``) through ``AccessControlledModelViewSet``
  could move an object, such as a ``RoleAssignment``, into a context where the user
  had no permission (#1). Updates are now also authorized against the object as
  saved (see **Changed**). Bypasses closed along the way: DRF-composed permissions,
  contexts derived by ``save()``, ``Serializer.update()``, signals, many-to-many
  fields or a ``cached_property``, read replicas, models routed to another
  database, and an update to the user's own ``RoleAssignment`` granting the
  permission that authorizes it (``policy_for`` now computes the user's grants once
  per request and caches them on the request).
* ``IsAuthorized`` checks objects with multiple ``rbac_contexts`` against each of
  them (permission in any one suffices) instead of failing; an object with no
  contexts is denied, except to superusers.
* ``PATCH`` on ``RoleViewSet`` no longer raises ``TypeError``.

**Changed:**

* After an update is saved, the RBAC permissions (``IsAuthorized`` and subclasses,
  including those inside ``&``, ``|`` and ``~``) are checked against the saved
  object, so a change of context needs the permission in the destination as well
  as in the current context; a denial (403) rolls the save back. Only the RBAC
  permissions are re-run, and **every** one of them must allow: with
  ``X | IsAuthorized``, the destination still needs RBAC permission even when ``X``
  allowed the request. Application permissions are not re-run against the new
  state.
* An update that changes an object's ``rbac_context`` also needs the permission in
  its new value, whatever ``contexts_for`` reports (``rbac_contexts``, a queryset
  annotation or an override), because ``RbacFilter`` lists objects by
  ``rbac_context``. This does not apply to creates (#6).
* ``perform_create`` and ``perform_update`` run the save and these checks in a
  transaction on the model's write database (``router.db_for_write``) and check a
  fresh instance read from it (through ``get_queryset()``, so annotations are
  present), never a read replica. They accept ``**save_kwargs`` and call
  ``serializer.save(**save_kwargs)``, so overrides pass extra save arguments (e.g.
  ``owner=self.request.user``) through ``super()``.
* Create and update responses show the object as re-read from the write database
  (including changes made by ``save()`` or signals).
* Writes into the reserved context namespace are rejected with 400 (code
  ``reserved_rbac_context``) and rolled back: any context that, after Unicode NFKC
  normalisation, removing invisible characters (categories Cf, Cc, Mn and Me, and
  the fillers U+115F, U+1160, U+3164, U+FFA0 and U+2800) and stripping whitespace,
  starts with ``__`` (such as ``__SOME_CONTEXT__``). All of an object's
  contexts are checked: ``rbac_context``, ``rbac_contexts`` (including a queryset
  annotation of that name), and those from permission classes overriding
  ``contexts_for``. A bulk create (``many=True``) checks each created object.
  Existing rows are not affected.
* An update that changes the object's primary key is rejected with 400 (code
  ``primary_key_changed``) and rolled back; with a writable primary key it could
  otherwise overwrite another object's row.
* An object saved to a database other than its write database raises
  ``ImproperlyConfigured``, since the save could be neither checked nor rolled
  back.

**Added:**

* ``AccessControlledModelViewSet.get_post_save_permissions()`` and
  ``check_post_save_permissions(request, obj, new_rbac_context=None)``: the
  permissions checked against the saved object, and the check itself. Override the
  former (e.g. return ``[]``) to change or skip the post-save check.
* ``IsAuthorized.has_context_permission(request, view, obj, context)``: whether the
  request is allowed in one given context; used for a moved ``rbac_context`` column
  and by ``has_object_permission``.
* ``AccessControlledModelViewSet.check_not_reserved_context(instance)`` and
  ``model_for(serializer)`` as extension points.

**Notes:**

* Subclasses overriding ``perform_create`` or ``perform_update`` must call
  ``super()`` (passing extra save arguments as keyword arguments), or these checks
  are skipped.
* A create whose serializer leaves no saved model instance in
  ``serializer.instance`` (e.g. ``create()`` returns an unsaved object), or such an
  item in a ``many=True`` result (a list, QuerySet or other iterable), is not
  checked after saving, since there is nothing persisted to check.
* Bulk (``many=True``) updates are not supported: ``perform_update`` raises
  ``ImproperlyConfigured`` before saving, because they bypass DRF's pre-save
  ``get_object()`` check. A subclass offering bulk updates must authorize them
  itself.
* Rolling back a denied write requires a transactional database backend; with e.g.
  MySQL's MyISAM the error is returned but the write remains. Side effects outside
  the database, such as signal handlers sending email, may run before a rollback.
* ``router.db_for_write`` for access-controlled models must not depend on mutable
  instance fields such as ``rbac_context``; otherwise a save can be routed to a
  different database than the transaction and is not rolled back (#42).
* Models whose ``rbac_contexts`` come from relations must query the instance's own
  database, e.g. ``self.tags.using(self._state.db)``; otherwise a read router may
  answer them from a replica that does not see the update.
* The pre-save object check runs outside the transaction, so a concurrent change
  between it and the save can be overwritten (#43).

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


