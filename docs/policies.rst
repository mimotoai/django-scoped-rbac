.. _Policies:

********
Policies
********

A user's policy says which *permissions* (an action IRI and a resource type IRI) they
hold in which *contexts*, optionally only when *conditions* on the resource hold. It
is merged from the ``SCOPED_RBAC`` settings defaults and the user's role assignments
(each role's definition applies in the context of the assignment, and also in the
special context ``__SOME_CONTEXT__`` used for list and create checks).


Policy JSON
===========

Role definitions and settings defaults are written in the policy JSON grammar. A
role definition starts at the action level; a settings default starts one level
higher, at the context level. At each level:

- ``true`` allows everything below it, and ``false`` nothing.
- A string, or a list of strings, names the keys under which everything is allowed,
  e.g. ``["http.GET", "http.PUT"]``.
- An object maps keys to the policy below them, e.g.
  ``{"http.GET": ["app.Thing"], "http.PUT": true}``.
- A list may also contain ``{"<key>": "<CEL expression>"}`` items, which allow the key
  when the condition holds, e.g. ``[{"http.DELETE": "status == 'draft'"}]``.
- A *condition* ``{"condition": <condition>}`` allows when the condition holds,
  whatever the remaining keys.

A condition is a CEL expression string, or an operator configuration such as
``{"operator": "is_allowed_transition", "field": "status"}``.

Messages
--------

A condition object may carry a ``"message"`` describing the condition, for example
for a client to show when it is not met:

.. code-block:: json

   {
     "http.PUT": {
       "app.Thing": {"condition": "status == 'draft'", "message": "Only drafts can be edited"}
     }
   }

The value of an item in the list form may be such an object too:
``[{"http.DELETE": {"condition": "status == 'draft'", "message": "..."}}]``. The same
condition with a different message is a different condition.

Any key: ``"*"``
----------------

The key ``"*"`` matches any key at its level: any context in a settings default, any
action, or any resource type. ``{"http.GET": {"*": true}}`` is the same as
``{"http.GET": true}``, and ``{"*": ["app.Thing"]}`` allows every action on
``app.Thing``. ``"*"`` is therefore reserved and cannot name a context, action or
resource type. A list request is not restricted to particular contexts when the
user's policy has grants in any context (``"*"``), as when it allows everything.


Evaluation
==========

Evaluating a policy for a request gives one of three decisions
(:class:`scoped_rbac.policy.Decision`): ``ALLOWED``, ``DENIED`` or ``UNDETERMINED``.
``UNDETERMINED`` means a condition could not be decided, for instance because there
is no resource yet or it lacks a value the condition refers to. The server allows a
request only when the decision is ``ALLOWED``; a client may choose to treat
``UNDETERMINED`` as "possibly allowed", for example when deciding what to offer a
user before a resource exists.

A policy is a tree of nodes (:class:`scoped_rbac.policy.PolicyNode`). A request's
keys are its context, action IRI and resource type IRI. Starting at the root and
stopping at the first ``ALLOWED``:

#. a node that allows everything is ``ALLOWED``;
#. the entry for the next key is evaluated with the remaining keys, then the
   ``"*"`` entry;
#. the node's conditions are evaluated, in order.

The decision is ``ALLOWED`` if any of these is, otherwise ``UNDETERMINED`` if any is,
otherwise ``DENIED``.

Conditions:

- A CEL expression is ``ALLOWED`` when it evaluates to ``true`` and ``DENIED`` when
  ``false``. An evaluation error (such as a missing variable, which includes any
  variable when there is no resource) or a non-boolean result is ``UNDETERMINED``.
  The resource's top-level members are the expression's variables.
- An operator function is called with the resource and its configuration. A result
  of ``None`` is ``UNDETERMINED``; otherwise a truthy result is ``ALLOWED`` and a
  falsy one ``DENIED``. An operator can return ``None`` when it cannot tell, e.g.
  without a resource.

``RootPolicy.evaluate(permission, context, resource)`` gives the decision,
``RootPolicy.should_allow`` is ``True`` only for ``ALLOWED``, and
``RootPolicy.explain`` also lists each condition evaluated to reach the decision,
with its own decision and message:

.. code-block:: python

   explanation = policy.explain(Permission("http.PUT", "app.Thing"), "ctx", draft)
   explanation.to_json()
   # {"decision": "denied",
   #  "conditions": [{"condition": "status == 'draft'",
   #                  "message": "Only drafts can be edited",
   #                  "decision": "denied"}]}

Merging policies (``sum_with``) is a logical OR and never changes the policies
merged.


Wire format
===========

``GET /policy`` returns the user's policy (``RootPolicy.to_json()``) in a format with
exactly three levels of keys, context, action IRI and resource type IRI, for clients
to evaluate as the server does. At each level the keys are names or ``"*"``, and a
client unions the entry for the name with the ``"*"`` entry. A leaf (at the resource
type level) is ``true`` or ``{"conditions": [<condition>, ...]}``, where each
condition is written as in policy JSON, with its message if it has one.

- Grants that apply whatever the remaining keys are under a chain of ``"*"`` keys:
  a superuser's policy is ``{"*": {"*": {"*": true}}}``, and a role
  ``[{"http.DELETE": "status == 'draft'"}]`` assigned in ``ctx`` gives
  ``{"ctx": {"http.DELETE": {"*": {"conditions": [{"condition": "status == 'draft'"}]}}}}``.
- An entry for a name does not repeat what the ``"*"`` entry grants.
- Leaves that grant nothing, and then empty objects, are left out; a user with no
  grants gets ``{}``.
- Keys are sorted. ``__SOME_CONTEXT__`` appears as an ordinary context.

``RootPolicy.from_json(wire)`` reads the format back into a policy that evaluates
and explains every request as the original does.

For example, an editor role assigned in ``project-1``:

.. code-block:: json

   {
     "__SOME_CONTEXT__": {
       "http.GET": {"app.Thing": true},
       "http.PUT": {"app.Thing": {"conditions": [{"condition": "status == 'draft'"}]}}
     },
     "project-1": {
       "http.GET": {"app.Thing": true},
       "http.PUT": {"app.Thing": {"conditions": [{"condition": "status == 'draft'"}]}}
     }
   }

Conformance fixtures
--------------------

``tests/conformance`` in the source repository holds language-neutral test cases,
generated with this engine, for other implementations: policies given as policy JSON
or in the wire format, their expected wire format, and requests with their expected
decisions and explanations. Its ``README.md`` describes the format.
