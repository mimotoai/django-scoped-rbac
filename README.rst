==================
django_scoped_rbac
==================

.. image:: https://gitlab.com/openteams/django-scoped-rbac/badges/master/pipeline.svg
   :target: https://gitlab.com/openteams/django-scoped-rbac/-/pipelines

A rich and flexible Django application for role-based access control within
distinct access control scopes supporting Django Rest Framework.

Motivation
----------

* Support multiple security contexts within an application, rather than having the
  application serve as the single security context.
* Support a model of security context that can be enforced at the query level within the
  database. For example - list all resources within the contexts the user is authorized
  to list resources.
* Support assignment of roles within a security context.
* Support an extensible mechanism for conditional policy expressions for permissions.
* Support a JSON representation of the total permissions granted to a user for all
  security contexts that can be shared with browser and other clients to enable
  permissions-informed disclosure UI and UX


Support multiple security contexts within an application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most RBAC systems provide a simple permission model to answer permissions. For example,
is the user authorized to POST a comment. In an application that supports multiple
security contexts the relevant context is an additional parameter required to determine
if the user is authorised; that is is the user authorized to POST a comment to this
project vs another project. A user may be authorized to POST a comment to one project,
but not another.


Support for security contexts at the query level
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If every object has a security context property it's possible to always secure the
queries executed for a user request by adding the user's authorized security contexts as
an "IN" condition restricting the scope of the query.


Support assignment of roles within a security context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In most RBAC systems a user is assigned a role that is applicable across the entire
application. For example, a user may have a `Commenter` role granting the user the
permission to post comments anywhere comments may be posted within the application. An
application that supports the assignment of a role within the scope of a specific
security context can restrict the assignment of the `Commenter` role to specific areas
of an application. For example, a user may be assigned the `Commenter` role in `Project
1` but not `Project 2`.


Support an extensible mechanism for conditional policy expressions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Another limitation of most RBAC systems is the simplicity of their permissions - you are
either authorized to perform an action or not. Supporting an extensible mechanism for
conditional policy expression means that a permission may be conditionally granted
dependant upon a variety of factors. For example, you may be granted the permission to
comment within a project only when a target resource within the scope of that project is
"open for community comments" vs "open for drafter comments".


Support JSON representation of total permissions granted
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If a user has permission to perform an action, such as update a resource, it should be
possible for a client to determine that this is the case and be able to decide whether
to disclose editing capabilty for the resource to the user. That is, if I'm not
authorised to edit a resource the UI shouldn't offer me the opportunity to edit the
resource.

Providing a JSON representation of the user's total permissions, and a Javascript
implementation of the permissions policy engine, can provide a much richer user
experience.


Installation
============

Requires Python 3.11+, Django 5.2+ and Django REST Framework 3.15+.

.. code-block:: shell

   uv add django-scoped-rbac   # or: pip install django-scoped-rbac

Add ``"scoped_rbac"`` to ``INSTALLED_APPS`` and configure policies with the
``SCOPED_RBAC`` setting.


Conditional policy expressions
==============================

Policy conditions are written in the `Common Expression Language
<https://cel.dev>`_ and evaluated with Google's `cel-expr-python
<https://github.com/cel-expr/cel-python>`_ runtime. Each top-level key of the resource
being authorized is available as a variable, for example ``content.status == "open"``.
An expression that fails to evaluate denies access.

Custom functions are registered with ``CEL_FUNCTIONS``. Because the CEL runtime
dispatches on argument types, each function's parameters must be annotated with
``bool``, ``int``, ``float``, ``str``, ``bytes``, ``dict`` or ``list``; a function that
needs several signatures can be given as a ``cel_expr_python.cel.FunctionDecl``
instead:

.. code-block:: python

   # myapp/workflow.py
   def is_allowed_transition(current: str, proposed: str) -> bool:
       ...

   # settings.py
   SCOPED_RBAC = {
       "CEL_FUNCTIONS": {
           "is_allowed_transition": "myapp.workflow.is_allowed_transition",
       },
   }


Development
===========

The project is managed with `uv <https://docs.astral.sh/uv/>`_:

.. code-block:: shell

   uv sync                              # create .venv with the dev dependencies
   uv run pytest                        # run the tests with coverage
   uv run ruff check && uv run ruff format --check
   uv run --group docs make -C docs html   # build the docs into build/sphinx/html
