# Policy engine conformance fixtures

Language-neutral test cases for implementations of the django-scoped-rbac policy
engine (such as a JavaScript or C++ port). The Python engine passes every case
(`tests/test_conformance.py`). The fixtures are generated: change the cases in
`generate.py` (or the engine), then run, from the repository root:

```shell
uv run python tests/conformance/generate.py
```

The policy JSON grammar, the wire format and the evaluation rules are described in
`docs/policies.rst`. This file covers what an implementation needs to run the
fixtures.

## Files

Each `fixtures/*.json` file is `{"description": <string>, "cases": [<case>, ...]}`.

A case is an object with:

- `name`: unique within its file.
- `description` (optional).
- The policy's inputs, either:
  - authoring inputs: `defaults` (optional, a list of settings-default policies in
    the policy JSON grammar, whose top level names contexts) and/or `assignments`
    (optional, a list of `{"definition": <role definition in the policy JSON
    grammar>, "context": <string>}`); or
  - `wire_input`: a policy in the wire format.
- `wire`: the policy's expected wire format (what `GET /policy` returns).
- `probes`: a list of requests with their expected outcome:
  `{"context", "action", "resource_type"}` (strings), `"resource"` (any JSON value;
  `null` for no resource), `"expected"` (`"allowed"`, `"denied"` or
  `"undetermined"`), and `"conditions"`: the conditions evaluated to reach the
  decision, in order, each distinct condition once, as the condition's wire JSON
  plus its `"decision"`.

## Building the policy from authoring inputs

As the server builds a user's policy:

1. Start with the empty policy.
2. For each default, in order: merge it at the top level, then merge each of its
   context-level entries, except a `"*"` context, under the context
   `"__SOME_CONTEXT__"`. (A default's own top-level conditions are not copied.)
3. For each assignment, in order: merge the role definition under its context, then
   under `"__SOME_CONTEXT__"`.

Merging is a logical OR: allow-all is or-ed, entries are merged key by key, and
conditions are concatenated, left then right, keeping the first of any exact
duplicates (the same condition with a different message is not a duplicate).

## Running a case

For each way the case gives its policy (its authoring inputs or `wire_input`, and
its expected `wire`), build the policy, then check that:

- its wire format equals `wire` exactly (objects compare as JSON objects; condition
  lists in order), and
- every probe evaluates to `expected`, with `conditions` as listed.

Evaluating a probe walks the keys context, action, resource type. At a node
(stopping at the first `allowed`): allow-all is `allowed`; then the entry for the
key, then the `"*"` entry (once, if the key is itself `"*"`), each with the
remaining keys; then the node's conditions in order. The result is `allowed` if
any part is, otherwise `undetermined` if any part is, otherwise `denied`.

Resources in the fixtures are JSON objects, `null` or, for operators only, `true`.
Numbers in resources and operator configurations are integers.

## Conditions

`{"condition": "<CEL>"}`: a [CEL](https://cel.dev) expression, compiled without
type checking, whose variables are the resource object's top-level members (none if
the resource is `null`). A `true` result is `allowed`, `false` is `denied`, and an
evaluation error (such as a missing variable or field) or a non-boolean result is
`undetermined`.

`{"condition": {"operator": "<name>", ...configuration}}`: a registered operator,
called with the resource and the whole configuration object. A `null` (`None`)
result is `undetermined`; otherwise a truthy result is `allowed` and a falsy one
`denied`. The fixtures use two operators:

- `istrue`: `allowed` if the resource is `true`, or an object whose member `"a"`
  equals `3`; otherwise `denied`. Never `undetermined`.
- `a_at_least` (configuration `{"operator": "a_at_least", "min": <number>}`):
  `undetermined` if the resource is not an object, or its member `"a"` is missing
  or not a number (booleans are not numbers); otherwise `allowed` if `a >= min`,
  else `denied`.

Either form may have a `"message"` string, which is part of the condition.
