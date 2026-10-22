"""The policy wire format: `RootPolicy.to_json` (served at /policy) and
`RootPolicy.from_json` (GitLab issue #28).

The value is a JSON object with exactly three levels of keys: context, action IRI,
resource type IRI. A key is a name or "*" (any), and a client unions the specific
key and "*" at each level. A leaf is `true` or `{"conditions": [...]}`."""

import itertools
import json

import pytest

from scoped_rbac.policy import (
    POLICY_TRUE,
    Expression,
    Operator,
    Permission,
    PolicyNode,
    RootPolicy,
    policy_from_json,
)
from scoped_rbac.rbac_contexts import SOME_CONTEXT

from .test_policy_merge_properties import POLICIES as MERGE_POOL

A1 = {"condition": "a == 1"}
A2_MESSAGE = {"condition": "a == 2", "message": "a must be 2"}
ISTRUE = {"condition": {"operator": "istrue"}}


def root(*json_policies, **json_roles):
    """A RootPolicy merging settings-default style `json_policies` (top level =
    contexts) and `json_roles` (role definitions) keyed by context."""
    policy = RootPolicy()
    for json_policy in json_policies:
        policy.add_policy(policy_from_json(json_policy))
    for context, definition in json_roles.items():
        policy.add_json_policy_for_context(definition, context)
    return policy


@pytest.mark.parametrize(
    "policy, wire",
    [
        (RootPolicy(), {}),
        (root(True), {"*": {"*": {"*": True}}}),
        (root(A1), {"*": {"*": {"*": {"conditions": [A1]}}}}),
        (
            root(ctx2=[{"http.DELETE": A2_MESSAGE}]),
            {"ctx2": {"http.DELETE": {"*": {"conditions": [A2_MESSAGE]}}}},
        ),
        (root(ctx=A1), {"ctx": {"*": {"*": {"conditions": [A1]}}}}),
        (root(ctx=True), {"ctx": {"*": {"*": True}}}),
        (
            root(ctx={"GET": ["Thing", "Other"], "PUT": True}),
            {"ctx": {"GET": {"Other": True, "Thing": True}, "PUT": {"*": True}}},
        ),
        (
            root(ctx={"GET": {"Thing": ISTRUE}}),
            {"ctx": {"GET": {"Thing": {"conditions": [ISTRUE]}}}},
        ),
        # A specific key does not repeat what "*" grants.
        (
            root(A1, ctx={"GET": {"Thing": A2_MESSAGE}}),
            {
                "*": {"*": {"*": {"conditions": [A1]}}},
                "ctx": {"GET": {"Thing": {"conditions": [A2_MESSAGE]}}},
            },
        ),
        # Grants of a node and of its "*" child share the "*" chain, in that order.
        (
            root(ctx={"*": {"*": A1}}).add_policy_for_context(
                policy_from_json(A2_MESSAGE), "ctx"
            ),
            {"ctx": {"*": {"*": {"conditions": [A1, A2_MESSAGE]}}}},
        ),
        # Leaves that grant nothing are omitted, and then their empty parents.
        (root(ctx={"GET": [], "PUT": False}), {}),
        (root({"ctx": False}), {}),
        # Below the resource type level nothing is reachable.
        (root(ctx={"GET": {"Thing": "x"}}), {}),
        # Allow-all subsumes conditions and children.
        (root(A1, True, ctx={"GET": ["Thing"]}), {"*": {"*": {"*": True}}}),
    ],
    ids=repr,
)
def test_to_json(policy, wire):
    assert policy.to_json() == wire
    assert RootPolicy.from_json(wire).to_json() == wire


def test_some_context_is_an_ordinary_context():
    policy = root(ctx={"GET": ["Thing"]})
    policy.add_json_policy_for_context({"GET": ["Thing"]}, SOME_CONTEXT)

    assert policy.to_json() == {
        "__SOME_CONTEXT__": {"GET": {"Thing": True}},
        "ctx": {"GET": {"Thing": True}},
    }


def test_keys_are_sorted():
    policy = root(b={"z": ["b", "a"], "y": True}, a=[{"x": "true"}])

    serialised = json.dumps(policy.to_json())

    assert serialised == json.dumps(json.loads(serialised), sort_keys=True)
    assert list(policy.to_json()) == ["a", "b"]


def test_from_json_builds_the_tree():
    wire = {
        "*": {"*": {"*": {"conditions": [A1]}}},
        "ctx": {"GET": {"Thing": True, "*": {"conditions": [A2_MESSAGE, ISTRUE]}}},
    }

    policy = RootPolicy.from_json(wire).policy

    any_leaf = PolicyNode(conditions=[Expression("a == 1")])
    assert policy == PolicyNode(
        children={
            "*": PolicyNode(children={"*": PolicyNode(children={"*": any_leaf})}),
            "ctx": PolicyNode(
                children={
                    "GET": PolicyNode(
                        children={
                            "Thing": POLICY_TRUE,
                            "*": PolicyNode(
                                conditions=[
                                    Expression("a == 2", message="a must be 2"),
                                    Operator({"operator": "istrue"}),
                                ]
                            ),
                        }
                    )
                }
            ),
        }
    )


@pytest.mark.parametrize(
    "wire",
    [
        True,
        [],
        {"ctx": True},
        {"ctx": {"GET": True}},
        {"ctx": {"GET": {"Thing": False}}},
        {"ctx": {"GET": {"Thing": {"conditions": [A1], "other": 1}}}},
        {"ctx": {"GET": {"Thing": {"conditions": A1}}}},
        {"ctx": {"GET": {"Thing": {"conditions": ["a == 1"]}}}},
        {"ctx": {"GET": {"Thing": {"conditions": [{"condition": 1}]}}}},
        {"ctx": {"GET": {"Thing": {"conditions": [{"condition": {"x": 1}}]}}}},
        {"ctx": {"GET": {"Thing": {"conditions": [{**A1, "message": 1}]}}}},
        {"ctx": {"GET": {"Thing": {"conditions": [{**A1, "other": 1}]}}}},
    ],
    ids=repr,
)
def test_from_json_rejects_malformed_input(wire):
    with pytest.raises(ValueError, match="Invalid policy wire format"):
        RootPolicy.from_json(wire)


# Round trip: for every probe, `from_json(to_json(p))` evaluates and explains as `p`
# does, and `to_json` is a fixpoint.

KEYS = ("x", "y", "z", "w", "*")
RESOURCES = ({"a": 1}, {"a": 2}, {"a": 3}, {}, None, True)
PROBES = [
    (Permission(action, resource_type), context, resource)
    for context, action, resource_type in itertools.product(KEYS, repeat=3)
    for resource in RESOURCES
]


def outcome(policy, probe):
    permission, context, resource = probe
    try:
        return policy.explain(permission, context, resource)
    except TypeError as e:
        return repr(e)


def round_trip_cases():
    for name, (build, _) in MERGE_POOL.items():
        yield f"default {name}", lambda build=build: RootPolicy().add_policy(build())
        yield (
            f"role {name}",
            lambda build=build: RootPolicy().add_policy_for_context(build(), "x"),
        )
    for (a, (build_a, _)), (b, (build_b, _)) in itertools.combinations(
        MERGE_POOL.items(), 2
    ):
        yield (
            f"{a} in x, {b} in y and *",
            lambda build_a=build_a, build_b=build_b: (
                RootPolicy()
                .add_policy(build_a())
                .add_policy_for_context(build_b(), "y")
                .add_policy_for_context(build_b(), "*")
            ),
        )


ROUND_TRIP_CASES = dict(round_trip_cases())


@pytest.mark.parametrize("name", ROUND_TRIP_CASES)
def test_round_trip(name):
    policy = ROUND_TRIP_CASES[name]()

    wire = policy.to_json()
    copy = RootPolicy.from_json(json.loads(json.dumps(wire)))

    assert copy.to_json() == wire
    mismatches = [
        (probe, expected, actual)
        for probe in PROBES
        if (expected := outcome(policy, probe)) != (actual := outcome(copy, probe))
    ]
    assert not mismatches, mismatches[:3]
