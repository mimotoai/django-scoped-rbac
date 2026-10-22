import pytest

from scoped_rbac.policy import (
    POLICY_FALSE,
    POLICY_TRUE,
    CompoundPolicy,
    Expression,
    ExpressionList,
    Operator,
    Permission,
    PolicyDict,
    PolicyNode,
    PolicySet,
    RootPolicy,
    policy_from_json,
)

permission_one = Permission(action="GET", resource_type="One")
permission_two = Permission(action="GET", resource_type="Two")
permission_never_used = Permission(action="NEVER", resource_type="shouldn't matter")
permission_action_only = Permission(action="GET", resource_type=None)


class TestPolicyTrue:
    def test_should_allow(self):
        assert POLICY_TRUE.should_allow("anything") is True

    def test_sum_with_policy_true(self):
        assert POLICY_TRUE.sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        assert POLICY_TRUE.sum_with(POLICY_FALSE) is POLICY_TRUE

    def test_to_json(self):
        assert POLICY_TRUE.to_json() is True


class TestPolicyFalse:
    def test_should_allow(self):
        assert POLICY_FALSE.should_allow("anything") is False

    def test_sum_with_policy_true(self):
        assert POLICY_FALSE.sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        assert POLICY_FALSE.sum_with(POLICY_FALSE) is POLICY_FALSE

    def test_to_json(self):
        assert POLICY_FALSE.to_json() is False


def legacy(constructor, *args, **kwargs):
    """Build a policy with one of the deprecated constructors of the node classes
    before 0.10, which return the equivalent `PolicyNode`."""
    with pytest.deprecated_call():
        return constructor(*args, **kwargs)


class TestSet:
    """A set of keys, each allowing everything below it (formerly `PolicySet`)."""

    @pytest.mark.parametrize(
        "build",
        [lambda *keys: policy_from_json(list(keys)), lambda *k: legacy(PolicySet, *k)],
        ids=["json", "legacy"],
    )
    def test_should_allow(self, build):
        policy = build()
        assert policy.should_allow("one") is False
        assert policy.should_allow("two") is False
        assert policy.should_allow("three") is False

        policy = build("one", "two")
        assert policy.should_allow("one") is True
        assert policy.should_allow("one", "anything") is True
        assert policy.should_allow("two") is True
        assert policy.should_allow("three") is False
        assert policy.should_allow() is False

    def test_sum_with_policy_true(self):
        assert policy_from_json([]).sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        policy = policy_from_json(["one"])
        assert policy.sum_with(POLICY_FALSE) is policy

    def test_sum_with_set(self):
        policy1 = policy_from_json(["one", "two"])
        policy2 = policy_from_json("three")
        policy_sum = policy1.sum_with(policy2)
        assert policy_sum is not policy1
        assert policy_sum is not policy2
        assert policy_sum.should_allow("one") is True
        assert policy_sum.should_allow("two") is True
        assert policy_sum.should_allow("three") is True
        assert policy_sum.should_allow("four") is False

    def test_to_json(self):
        policy = policy_from_json(["two", "one"])
        assert policy.to_json() == {"children": {"one": True, "two": True}}


class TestDict:
    """Keys each with their own policy (formerly `PolicyDict`)."""

    @staticmethod
    def example():
        return PolicyNode(
            children={
                "one": POLICY_TRUE,
                "two": policy_from_json(["a", "b"]),
                "three": PolicyNode(children={"foo": POLICY_TRUE}),
                "context": policy_from_json({"action": ["resource1", "resource2"]}),
            }
        )

    @pytest.mark.parametrize(
        "build",
        [
            lambda: TestDict.example(),
            lambda: legacy(PolicyDict, TestDict.example().children),
        ],
        ids=["node", "legacy"],
    )
    def test_should_allow(self, build):
        policy = build()
        assert policy.should_allow("anything") is False
        assert policy.should_allow("one") is True
        assert policy.should_allow("two", "a") is True
        assert policy.should_allow("two", "b") is True
        assert policy.should_allow("two", "anything") is False
        assert policy.should_allow("three", "foo") is True
        assert policy.should_allow("three", "anything") is False
        assert policy.should_allow("context", "action", "resource1") is True
        assert policy.should_allow("context", "action", "resource2") is True
        assert policy.should_allow("context", "action", "resource3") is False

    def test_sum_with_policy_true(self):
        policy = policy_from_json({"one": True})
        assert policy.sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        policy = policy_from_json({"one": True})
        assert policy.sum_with(POLICY_FALSE) is policy

    def test_sum_with_set(self):
        policy = policy_from_json({"one": True})
        policy = policy.sum_with(policy_from_json("two"))
        assert policy.should_allow("one") is True
        assert policy.should_allow("two") is True
        assert policy.should_allow("three") is False

    def test_sum_with_dict(self):
        policy1 = PolicyNode(
            children={
                "1": POLICY_TRUE,
                "2": PolicyNode(
                    children={
                        "2_1": POLICY_TRUE,
                        "2_2": policy_from_json(["2_2_1", "2_2_2"]),
                    }
                ),
            }
        )
        policy2 = PolicyNode(
            children={
                "1": policy_from_json("one"),
                "2": policy_from_json(["3_1", "3_2"]),
                "3": POLICY_TRUE,
            }
        )

        sum_policy = policy1.sum_with(policy2)
        assert sum_policy.should_allow("1", "anything") is True
        assert sum_policy.should_allow("2", "2_1", "anything") is True
        assert sum_policy.should_allow("2", "2_2") is False
        assert sum_policy.should_allow("2", "2_2", "2_2_1") is True
        assert sum_policy.should_allow("2", "2_2", "2_2_2") is True
        assert sum_policy.should_allow("2", "2_2", "anything") is False
        assert sum_policy.should_allow("2", "3_1", "anything") is True
        assert sum_policy.should_allow("2", "3_2", "anything") is True
        assert sum_policy.should_allow("2", "anything", "anything") is False
        assert sum_policy.should_allow("3", "anything", "anything") is True
        assert sum_policy.should_allow("anything", "anything", "anything") is False

    def test_to_json(self):
        assert self.example().to_json() == {
            "children": {
                "context": {
                    "children": {
                        "action": {"children": {"resource1": True, "resource2": True}}
                    }
                },
                "one": True,
                "three": {"children": {"foo": True}},
                "two": {"children": {"a": True, "b": True}},
            }
        }


def test_operator():
    # refer to conftest.py for registration of the istrue operator
    operator = Operator({"operator": "istrue"})
    assert operator.should_allow(resource=False) is False
    assert operator.should_allow(resource=42) is False
    assert operator.should_allow(resource=True) is True


class TestMerging:
    """Regression tests for `sum_with` (GitLab issues #2 and #3).

    The merge contract is tests/test_policy_merge_properties.py. Policies of the
    node classes before 0.10 are built here with their deprecated constructors.
    """

    @pytest.mark.parametrize(
        "first, second",
        [
            ([{"http.GET": "status == 'ok'"}], {"http.GET": ["Other"]}),
            ({"condition": "status == 'ok'"}, {"http.GET": ["Thing"]}),
        ],
    )
    @pytest.mark.parametrize("reverse", [False, True])
    def test_conditional_and_plain_grants_merge(self, first, second, reverse):
        a, b = policy_from_json(first), policy_from_json(second)
        if reverse:
            a, b = b, a

        policy = a.sum_with(b)

        ok, not_ok = {"status": "ok"}, {"status": "no"}
        assert policy.should_allow("http.GET", "Anything", resource=ok) is True
        assert policy.should_allow("http.GET", "Anything", resource=not_ok) is False
        plain_type = "Other" if "Other" in str(second) else "Thing"
        assert policy.should_allow("http.GET", plain_type, resource=not_ok) is True

    @pytest.mark.parametrize("reverse", [False, True])
    def test_issue_3_resource_condition_merged_with_condition_list(self, reverse):
        resource_condition = policy_from_json(
            {"GET": {"Thing": {"condition": "c == 1"}}}
        )
        condition_list = policy_from_json(
            {"GET": [{"Thing": "a == 1"}, {"Thing": "b == 1"}]}
        )
        a, b = resource_condition, condition_list
        if reverse:
            a, b = b, a

        policy = a.sum_with(b)

        for allowed in ({"a": 1}, {"b": 1}, {"c": 1}):
            assert policy.should_allow("GET", "Thing", resource=allowed) is True
        assert policy.should_allow("GET", "Thing", resource={"a": 2}) is False
        assert policy.should_allow("GET", "Other", resource={"a": 1}) is False

    def test_compound_policies_merge(self):
        a = legacy(
            CompoundPolicy,
            policy_dict=legacy(PolicyDict, {"x": POLICY_TRUE}),
            expressions=legacy(ExpressionList, Expression("a == 1")),
        )
        b = legacy(
            CompoundPolicy,
            policy_set=legacy(PolicySet, "y"),
            expressions=legacy(ExpressionList, Expression("a == 2")),
        )

        policy = a.sum_with(b)

        assert policy.should_allow("x", resource={}) is True
        assert policy.should_allow("y", resource={}) is True
        assert policy.should_allow("z", resource={"a": 1}) is True
        assert policy.should_allow("z", resource={"a": 2}) is True
        assert policy.should_allow("z", resource={"a": 3}) is False

    def test_operator_merged_into_empty_compound_policy_is_kept(self):
        operator = Operator({"operator": "istrue"})

        merged = legacy(CompoundPolicy).sum_with(operator)

        assert merged.should_allow(resource=True) is True
        assert merged == PolicyNode(conditions=[operator])

    def test_merging_conditions_with_a_plain_grant(self):
        policy = Expression("a == 1").sum_with(policy_from_json("x"))

        assert policy == PolicyNode(
            children={"x": POLICY_TRUE}, conditions=[Expression("a == 1")]
        )
        assert policy.to_json() == {
            "children": {"x": True},
            "conditions": [{"condition": "a == 1"}],
        }

    def test_merged_conditions_keep_the_order_merged(self):
        e1, e2, e3 = Expression("a == 1"), Expression("a == 2"), Expression("a == 3")

        assert e1.sum_with(e2).conditions == (e1, e2)
        assert e1.sum_with(e2).sum_with(e3).conditions == (e1, e2, e3)
        assert e3.sum_with(e1.sum_with(e2)).conditions == (e3, e1, e2)
        assert e1.sum_with(e2).sum_with(e1).conditions == (e1, e2)
        assert policy_from_json([{"x": "a == 1"}]).sum_with(
            policy_from_json([{"x": "a == 2"}])
        ) == PolicyNode(children={"x": PolicyNode(conditions=[e1, e2])})

    OTHERS = {
        "expression": (lambda: Expression("a == 2"), set()),
        "list": (
            lambda: legacy(
                ExpressionList, Expression("a == 2"), Operator({"operator": "istrue"})
            ),
            set(),
        ),
        "set": (lambda: legacy(PolicySet, "x"), {"x"}),
        "dict": (lambda: legacy(PolicyDict, {"y": Expression("a == 2")}), {"y"}),
        "compound": (
            lambda: legacy(
                CompoundPolicy,
                policy_dict=legacy(PolicyDict, {"z": POLICY_TRUE}),
                expressions=legacy(ExpressionList, Expression("a == 2")),
            ),
            {"z"},
        ),
        "lone_compound": (
            lambda: legacy(CompoundPolicy, expressions=Expression("a == 2")),
            set(),
        ),
    }

    @pytest.mark.parametrize("other_name", OTHERS)
    @pytest.mark.parametrize(
        "lone",
        [Expression("a == 1"), Operator({"operator": "istrue"})],
        ids=["expression", "operator"],
    )
    @pytest.mark.parametrize("reverse", [False, True])
    def test_compound_policy_with_a_lone_condition_merges(
        self, lone, other_name, reverse
    ):
        # Settings may supply hand-built policies, whose `expressions` may be a lone
        # condition rather than an `ExpressionList`.
        build_other, other_contexts = self.OTHERS[other_name]
        other = build_other()
        compound = legacy(
            CompoundPolicy,
            policy_dict=legacy(PolicyDict, {"w": POLICY_TRUE}),
            expressions=lone,
        )
        a, b = (other, compound) if reverse else (compound, other)

        policy = a.sum_with(b)

        for keys in [(), ("w",), ("x",), ("y",), ("z",), ("v",)]:
            for resource in [{"a": 1}, {"a": 2}, {"a": 3}, {}]:
                expected = a.should_allow(*keys, resource=resource) or b.should_allow(
                    *keys, resource=resource
                )
                actual = policy.should_allow(*keys, resource=resource)
                assert actual is expected, (keys, resource)
        contexts = RootPolicy().add_policy(policy).get_contexts_for(permission_one)
        assert set(contexts) == {"w"} | other_contexts
        assert compound == PolicyNode(children={"w": POLICY_TRUE}, conditions=[lone])
        left = POLICY_FALSE.sum_with(a).conditions
        right = POLICY_FALSE.sum_with(b).conditions
        assert policy.conditions == left + tuple(c for c in right if c not in left)

    @pytest.mark.parametrize("reverse", [False, True])
    def test_compound_policy_with_a_lone_condition_keeps_condition_order(self, reverse):
        def hand():
            return legacy(
                CompoundPolicy,
                policy_dict=legacy(PolicyDict, {"w": POLICY_TRUE}),
                expressions=Expression("a == 1"),
            )

        def ordered(a, b):
            return b.sum_with(a) if reverse else a.sum_with(b)

        merged = ordered(hand(), policy_from_json({"condition": "a == 2"}))
        nested = ordered(
            PolicyNode(children={"x": hand()}), policy_from_json([{"x": "a == 2"}])
        )

        conditions = [Expression("a == 1"), Expression("a == 2")]
        if reverse:
            conditions.reverse()
        expected = PolicyNode(children={"w": POLICY_TRUE}, conditions=conditions)
        assert merged == expected
        assert nested == PolicyNode(children={"x": expected})

    @pytest.mark.parametrize(
        "expressions, build_other, expected",
        [
            (
                POLICY_FALSE,
                lambda: Expression("a == 2"),
                PolicyNode(
                    children={"w": POLICY_TRUE}, conditions=[Expression("a == 2")]
                ),
            ),
            (
                POLICY_FALSE,
                lambda: legacy(
                    ExpressionList, Expression("a == 2"), Expression("a == 3")
                ),
                PolicyNode(
                    children={"w": POLICY_TRUE},
                    conditions=[Expression("a == 2"), Expression("a == 3")],
                ),
            ),
            (POLICY_TRUE, lambda: Expression("a == 2"), POLICY_TRUE),
            (
                POLICY_TRUE,
                lambda: legacy(
                    ExpressionList, Expression("a == 2"), Expression("a == 3")
                ),
                POLICY_TRUE,
            ),
            *[
                (
                    boolean,
                    lambda: legacy(
                        CompoundPolicy,
                        policy_dict=legacy(PolicyDict, {"z": POLICY_TRUE}),
                        expressions=legacy(ExpressionList, Expression("a == 2")),
                    ),
                    expected,
                )
                for boolean, expected in (
                    (
                        POLICY_FALSE,
                        PolicyNode(
                            children={"w": POLICY_TRUE, "z": POLICY_TRUE},
                            conditions=[Expression("a == 2")],
                        ),
                    ),
                    (POLICY_TRUE, POLICY_TRUE),
                )
            ],
        ],
        ids=[
            "false-condition",
            "false-list",
            "true-condition",
            "true-list",
            "false-compound",
            "true-compound",
        ],
    )
    @pytest.mark.parametrize("reverse", [False, True])
    def test_compound_policy_with_boolean_expressions_merges(
        self, expressions, build_other, expected, reverse
    ):
        other = build_other()
        compound = legacy(
            CompoundPolicy,
            policy_dict=legacy(PolicyDict, {"w": POLICY_TRUE}),
            expressions=expressions,
        )
        a, b = (other, compound) if reverse else (compound, other)

        policy = a.sum_with(b)

        for keys in [(), ("w",), ("z",), ("v",)]:
            for resource in [{"a": 1}, {"a": 2}, {"a": 3}, {}]:
                expected_allowed = a.should_allow(
                    *keys, resource=resource
                ) or b.should_allow(*keys, resource=resource)
                actual = policy.should_allow(*keys, resource=resource)
                assert actual is expected_allowed, (keys, resource)
        assert policy == expected

    @pytest.mark.parametrize(
        "build",
        [
            lambda: Expression("a == 1"),
            lambda: Operator({"operator": "istrue"}),
            lambda: legacy(ExpressionList, Expression("a == 1")),
            lambda: legacy(PolicySet, "x"),
            lambda: legacy(PolicyDict, {"x": POLICY_TRUE}),
            lambda: legacy(
                CompoundPolicy, expressions=legacy(ExpressionList, Expression("a == 1"))
            ),
        ],
        ids=["expression", "operator", "list", "set", "dict", "compound"],
    )
    @pytest.mark.parametrize("other", [None, object(), {"x": True}], ids=repr)
    def test_merging_an_unsupported_type_raises(self, build, other):
        policy = build()
        with pytest.raises(NotImplementedError, match="Unsupported type"):
            policy.sum_with(other)
