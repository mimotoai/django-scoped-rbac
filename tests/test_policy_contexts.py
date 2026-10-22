"""The contexts a GET list is filtered to (`RootPolicy.get_contexts_for`) and the
grants `permissions.sum_policies` copies under `SOME_CONTEXT`, for every shape of
root policy."""

import pytest

from scoped_rbac.permissions import sum_policies
from scoped_rbac.policy import (
    POLICY_FALSE,
    POLICY_TRUE,
    Expression,
    Operator,
    Permission,
    PolicyNode,
    RootPolicy,
    policy_from_json,
)
from scoped_rbac.rbac_contexts import SOME_CONTEXT

GET_THING = Permission("GET", "Thing")
CONDITION = {"condition": "a == 1"}


def root_of(*json_policies):
    root = RootPolicy()
    for json_policy in json_policies:
        root.add_policy(policy_from_json(json_policy))
    return root


@pytest.mark.parametrize(
    "json_policies, contexts",
    [
        # As in 0.9.2: no restriction for allow-all, nothing, or only conditions.
        ([True], None),
        ([True, {"ctx1": True}], None),
        ([], None),
        ([False], None),
        ([CONDITION], None),
        ([CONDITION, {"condition": {"operator": "istrue"}}], None),
        # As in 0.9.2: a root with context grants is restricted to their contexts,
        # whatever its top-level conditions.
        ([{"ctx1": {"GET": ["Thing"]}, "ctx2": False}], {"ctx1", "ctx2"}),
        ([CONDITION, {"ctx1": True}], {"ctx1"}),
        ([{"ctx1": True}, CONDITION, ["ctx2"]], {"ctx1", "ctx2"}),
        # 0.9.2 left a root that was only a set of contexts unrestricted.
        (["ctx1"], {"ctx1"}),
        ([["ctx1", "ctx2"]], {"ctx1", "ctx2"}),
    ],
    ids=repr,
)
def test_get_contexts_for(json_policies, contexts):
    result = root_of(*json_policies).get_contexts_for(GET_THING)

    assert result == contexts if contexts is None else set(result) == contexts


@pytest.mark.parametrize("lone", [Expression("a == 1"), Operator({"operator": "x"})])
def test_get_contexts_for_a_lone_condition_root(lone):
    assert RootPolicy().add_policy(lone).get_contexts_for(GET_THING) is None


def test_sum_policies_copies_context_grants_to_some_context():
    total = RootPolicy()
    additional = policy_from_json(
        {"ctx1": {"GET": ["Thing"]}, "ctx2": {"PUT": {"Thing": "a == 1"}}}
    )

    sum_policies(total, additional)

    assert total.policy.children[SOME_CONTEXT] == policy_from_json(
        {"GET": ["Thing"], "PUT": {"Thing": CONDITION}}
    )
    assert total.should_allow(GET_THING, SOME_CONTEXT) is True
    assert total.should_allow(Permission("PUT", "Thing"), SOME_CONTEXT, {"a": 1})


def test_sum_policies_does_not_copy_top_level_conditions():
    total = RootPolicy()
    additional = policy_from_json(CONDITION).sum_with(policy_from_json({"ctx1": True}))

    sum_policies(total, additional)

    assert total.policy == PolicyNode(
        children={"ctx1": POLICY_TRUE, SOME_CONTEXT: POLICY_TRUE},
        conditions=[Expression("a == 1")],
    )


@pytest.mark.parametrize("additional", [POLICY_TRUE, POLICY_FALSE, Expression("true")])
def test_sum_policies_without_context_grants_copies_nothing(additional):
    total = RootPolicy()

    sum_policies(total, additional)

    assert SOME_CONTEXT not in total.policy.children
    assert total.policy == POLICY_FALSE.sum_with(additional)


def test_sum_policies_copies_a_set_of_contexts():
    """0.9.2 copied nothing for a default that was only a set of contexts, so it
    granted nothing in SOME_CONTEXT (e.g. for list requests)."""
    total = RootPolicy()

    sum_policies(total, policy_from_json(["ctx1"]))

    assert total.should_allow(GET_THING, SOME_CONTEXT) is True
    assert total.should_allow(GET_THING, "ctx2") is False


def test_get_contexts_for_any_context_is_unrestricted():
    root = root_of({"ctx1": True}, {"*": {"GET": ["Thing"]}})

    assert root.get_contexts_for(GET_THING) is None


def test_sum_policies_does_not_copy_any_context():
    total = RootPolicy()

    sum_policies(
        total, policy_from_json({"*": {"GET": ["Thing"]}, "ctx1": {"PUT": ["Thing"]}})
    )

    assert set(total.policy.children) == {"*", "ctx1", SOME_CONTEXT}
    assert total.policy.children[SOME_CONTEXT] == policy_from_json({"PUT": ["Thing"]})
    assert total.should_allow(GET_THING, SOME_CONTEXT) is True
