"""
Merging policies (`sum_with`) is a logical OR: a merged policy allows exactly what
either operand allows, whatever the order or grouping of the merge, and merging
changes neither operand (GitLab issues #2 and #3).

`permissions.policy_for` merges a user's roles in no fixed order, and every role is
also merged under `SOME_CONTEXT`, so any two roles sharing an action name meet here.

These tests use only the public policy behaviour: policies are built with
`policy_from_json` (and `sum_with`, for the shapes only a merge produces) and
compared with `should_allow` over a grid of probes.
"""

import itertools
from collections.abc import Mapping

import pytest

from scoped_rbac.policy import policy_from_json

# Probes: up to three keys (context, action, resource type), each from KEYS, where
# "w" appears in no policy, and a resource for the conditions.
KEYS = ("x", "y", "z", "w")
KEY_TUPLES = [
    keys for length in range(4) for keys in itertools.product(KEYS, repeat=length)
]
RESOURCES = ({"a": 1}, {"a": 2}, {"a": 3}, {}, None, True, False)
PROBES = [(keys, resource) for keys in KEY_TUPLES for resource in RESOURCES]

CONDITION_A1 = {"condition": "a == 1"}
CONDITION_A2 = {"condition": "a == 2"}
# The `istrue` operator is registered in tests/conftest.py: it allows the resource
# `True` and a mapping whose "a" is 3.
OPERATOR = {"condition": {"operator": "istrue"}}


def merge_json(*json_policies):
    total = policy_from_json(json_policies[0])
    for json_policy in json_policies[1:]:
        total = total.sum_with(policy_from_json(json_policy))
    return total


def from_json(json_policy):
    return lambda: policy_from_json(json_policy)


def merged(*json_policies):
    return lambda: merge_json(*json_policies)


# name -> (builder, contains an operator). A builder makes a fresh policy each call.
POLICIES = {
    "true": (from_json(True), False),
    "false": (from_json(False), False),
    "condition_a1": (from_json(CONDITION_A1), False),
    "condition_a2": (from_json(CONDITION_A2), False),
    "operator": (from_json(OPERATOR), True),
    "set_empty": (from_json([]), False),
    "set_x": (from_json("x"), False),
    "set_yz": (from_json(["y", "z"]), False),
    "dict_empty": (from_json({}), False),
    "dict_true_and_set": (from_json({"x": True, "z": ["y"]}), False),
    "dict_false_and_empty": (from_json({"x": False, "y": []}), False),
    # The #2 reproduction's shapes: a condition, and a plain grant, on an action.
    "dict_x_condition": (from_json([{"x": "a == 1"}]), False),
    "dict_x_set": (from_json({"x": ["y"]}), False),
    "dict_xy_condition": (from_json({"x": [{"y": "a == 1"}]}), False),
    "nested_3_levels": (
        from_json({"x": {"y": "z", "z": {"x": "a == 2", "y": True}}, "y": ["x", "z"]}),
        False,
    ),
    "nested_operator": (
        from_json({"y": {"x": [{"operator": "istrue"}], "z": True}}),
        True,
    ),
    "conditions_2": (merged(CONDITION_A1, CONDITION_A2), False),
    "condition_and_operator": (merged(CONDITION_A2, OPERATOR), True),
    "condition_or_dict": (merged(CONDITION_A2, {"x": {"y": "x"}}), False),
    "operator_or_set": (merged(OPERATOR, ["y"]), True),
    "nested_condition_or_set": (
        merged({"x": {"y": CONDITION_A1}}, {"x": {"y": ["z"]}}),
        False,
    ),
    "nested_conditions": (
        merged({"y": {"x": CONDITION_A1}}, {"y": {"x": OPERATOR}}),
        True,
    ),
    "operator_and_conditions": (merged(OPERATOR, CONDITION_A1, CONDITION_A2), True),
    # Conditions on an action (depth 1), and on a resource type (depth 2).
    "action_condition_or_set": (merged([{"x": "a == 1"}], {"x": ["y"]}), False),
    "resource_operator": (from_json({"x": {"y": OPERATOR}, "y": {"x": True}}), True),
    "resource_condition_and_operator": (
        merged({"x": {"y": CONDITION_A2}}, {"x": {"y": OPERATOR}}),
        True,
    ),
    "resource_operator_or_set": (
        merged({"x": {"y": OPERATOR}}, {"x": {"y": ["z"]}}),
        True,
    ),
}

# The pool's only constant policies; every other one allows some probes and denies
# others, and no two behave the same.
ALWAYS_ALLOW = {"true"}
ALWAYS_DENY = {"false", "set_empty", "dict_empty", "dict_false_and_empty"}

# A smaller pool for the three-way merges, covering every shape above.
TRIPLE_POLICIES = [
    "condition_a1",
    "operator",
    "set_x",
    "dict_x_condition",
    "nested_3_levels",
    "nested_operator",
    "conditions_2",
    "condition_or_dict",
    "operator_or_set",
    "nested_condition_or_set",
    "action_condition_or_set",
    "resource_operator",
]

RAISES = "raises"


def outcome(policy, probe):
    """`should_allow` for `probe`, or RAISES if evaluating a condition on resource
    data that is not a mapping raised (an evaluation error, issue #8)."""
    keys, resource = probe
    try:
        return policy.should_allow(*keys, resource=resource) is True
    except TypeError:
        if resource is None or isinstance(resource, Mapping):
            raise
        return RAISES


def outcomes(policy):
    return [outcome(policy, probe) for probe in PROBES]


def snapshot(policy, has_operator):
    """What must not change when `policy` is merged. (`to_json` of an operator is
    broken, issue #28.)"""
    return outcomes(policy), None if has_operator else policy.to_json()


def assert_allows_union(merged_policy, operand_outcomes, description):
    """`merged_policy` allows exactly the probes some operand allows, for every probe
    on which no operand raises."""
    mismatches = []
    checked = 0
    for index, probe in enumerate(PROBES):
        operands = [o[index] for o in operand_outcomes]
        if RAISES in operands:
            continue
        checked += 1
        expected = any(operands)
        try:
            actual = outcome(merged_policy, probe)
        except Exception as e:
            actual = repr(e)
        if actual != expected:
            mismatches.append((probe, expected, actual))
    assert checked
    assert not mismatches, (
        f"{description}: {len(mismatches)} of {checked} probes wrong, e.g. "
        f"(probe, expected, actual) {mismatches[:3]}"
    )


def test_pool_policies_are_distinct_and_not_constant():
    vectors = {name: outcomes(build()) for name, (build, _) in POLICIES.items()}

    for name in ALWAYS_ALLOW:
        assert set(vectors[name]) == {True}, name
    for name in ALWAYS_DENY:
        assert set(vectors[name]) == {False}, name
    varying = {
        name: vector
        for name, vector in vectors.items()
        if name not in ALWAYS_ALLOW | ALWAYS_DENY
    }
    assert [n for n, v in varying.items() if not (True in v and False in v)] == []
    same = [
        (a, b)
        for a, b in itertools.combinations(varying, 2)
        if varying[a] == varying[b]
    ]
    assert same == []


@pytest.mark.parametrize("name_b", POLICIES)
@pytest.mark.parametrize("name_a", POLICIES)
def test_merge_allows_exactly_the_union(name_a, name_b):
    (build_a, operator_a), (build_b, operator_b) = POLICIES[name_a], POLICIES[name_b]
    a, b = build_a(), build_b()
    before = [snapshot(a, operator_a), snapshot(b, operator_b)]

    merged_policy = a.sum_with(b)

    assert_allows_union(
        merged_policy, [before[0][0], before[1][0]], f"{name_a} + {name_b}"
    )
    if not (operator_a or operator_b):
        merged_policy.to_json()
    assert [snapshot(a, operator_a), snapshot(b, operator_b)] == before


@pytest.mark.parametrize(
    "names", list(itertools.combinations(TRIPLE_POLICIES, 3)), ids="+".join
)
def test_three_way_merge_allows_exactly_the_union_in_any_order(names):
    built = {name: POLICIES[name][0]() for name in names}
    has_operator = {name: POLICIES[name][1] for name in names}
    before = {name: snapshot(built[name], has_operator[name]) for name in names}
    operand_outcomes = [before[name][0] for name in names]

    for a, b, c in itertools.permutations(names):
        p, q, r = built[a], built[b], built[c]
        assert_allows_union(
            p.sum_with(q).sum_with(r), operand_outcomes, f"({a} + {b}) + {c}"
        )
        assert_allows_union(
            p.sum_with(q.sum_with(r)), operand_outcomes, f"{a} + ({b} + {c})"
        )

    assert {name: snapshot(built[name], has_operator[name]) for name in names} == before
