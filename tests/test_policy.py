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


class TestPolicySet:
    def test_should_allow(self):
        policy = PolicySet()
        assert policy.should_allow("one") is False
        assert policy.should_allow("two") is False
        assert policy.should_allow("three") is False

        policy = PolicySet("one", "two")
        assert policy.should_allow("one") is True
        assert policy.should_allow("two") is True
        assert policy.should_allow("three") is False

    def test_sum_with_policy_true(self):
        policy = PolicySet()
        assert policy.sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        policy = PolicySet()
        assert policy.sum_with(POLICY_FALSE) is policy

    def test_sum_with_policy_set(self):
        policy1 = PolicySet("one", "two")
        policy2 = PolicySet("three")
        policy_sum = policy1.sum_with(policy2)
        assert policy_sum is not policy1
        assert policy_sum is not policy2
        assert policy_sum.should_allow("one") is True
        assert policy_sum.should_allow("two") is True
        assert policy_sum.should_allow("three") is True
        assert policy_sum.should_allow("four") is False

    def test_to_json(self):
        policy = PolicySet("one", "two")
        policy_json = policy.to_json()
        assert isinstance(policy_json, list)
        assert "one" in policy_json
        assert "two" in policy_json


class TestPolicyDict:
    def test_should_allow(self):
        policy = PolicyDict(
            {
                "one": POLICY_TRUE,
                "two": PolicySet("a", "b"),
                "three": PolicyDict({"foo": POLICY_TRUE}),
                "context": PolicyDict({"action": PolicySet("resource1", "resource2")}),
            }
        )
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
        policy = PolicyDict({"one": POLICY_TRUE})
        assert policy.sum_with(POLICY_TRUE) is POLICY_TRUE

    def test_sum_with_policy_false(self):
        policy = PolicyDict({"one": POLICY_TRUE})
        assert policy.sum_with(POLICY_FALSE) is policy

    def test_sum_with_policy_set(self):
        policy = PolicyDict({"one": POLICY_TRUE})
        policy = policy.sum_with(PolicySet("two"))
        assert policy.should_allow("one") is True
        assert policy.should_allow("two") is True
        assert policy.should_allow("three") is False

    def test_sum_with_policy_dict(self):
        policy1 = PolicyDict(
            {
                "1": POLICY_TRUE,
                "2": PolicyDict(
                    {"2_1": POLICY_TRUE, "2_2": PolicySet("2_2_1", "2_2_2")}
                ),
            }
        )
        policy2 = PolicyDict(
            {"1": PolicySet("one"), "2": PolicySet("3_1", "3_2"), "3": POLICY_TRUE}
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
        policy = PolicyDict(
            {
                "one": POLICY_TRUE,
                "two": PolicySet("a", "b"),
                "three": PolicyDict({"foo": POLICY_TRUE}),
                "context": PolicyDict({"action": PolicySet("resource1", "resource2")}),
            }
        )
        policy_json = policy.to_json()
        assert policy_json["one"] is True
        assert "a" in policy_json["two"]
        assert "b" in policy_json["two"]
        assert policy_json["three"]["foo"] is True
        assert "resource1" in policy_json["context"]["action"]
        assert "resource2" in policy_json["context"]["action"]


def test_operator():
    # refer to conftest.py for registration of the istrue operator
    operator = Operator({"operator": "istrue"})
    assert operator.should_allow(resource=False) is False
    assert operator.should_allow(resource=42) is False
    assert operator.should_allow(resource=True) is True


class TestMerging:
    """Regression tests for `sum_with` (GitLab issues #2 and #3).

    The merge contract is tests/test_policy_merge_properties.py. Tests here marked
    "Characterisation" construct the current node classes directly or pin their
    `to_json` shapes; the planned PolicyNode rewrite may replace them.
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
        # Characterisation of the current node classes (see the class docstring).
        a = CompoundPolicy(
            policy_dict=PolicyDict({"x": POLICY_TRUE}),
            expressions=ExpressionList(Expression("a == 1")),
        )
        b = CompoundPolicy(
            policy_set=PolicySet("y"), expressions=ExpressionList(Expression("a == 2"))
        )

        policy = a.sum_with(b)

        assert policy.should_allow("x", resource={}) is True
        assert policy.should_allow("y", resource={}) is True
        assert policy.should_allow("z", resource={"a": 1}) is True
        assert policy.should_allow("z", resource={"a": 2}) is True
        assert policy.should_allow("z", resource={"a": 3}) is False

    def test_operator_merged_into_empty_compound_policy_is_kept(self):
        # Characterisation of the current node classes (see the class docstring).
        operator = Operator({"operator": "istrue"})

        assert CompoundPolicy().sum_with(operator).should_allow(resource=True) is True
        assert CompoundPolicy().add_expression(operator).should_allow(resource=True)

    def test_merging_conditions_with_a_plain_grant_to_json(self):
        # Characterisation of the current node classes (see the class docstring).
        policy = Expression("a == 1").sum_with(PolicySet("x"))

        assert policy.to_json() == {
            "expressions": ["a == 1"],
            "policy_dict": {"x": True},
        }

    def test_to_json_of_merges_that_already_worked_is_unchanged(self):
        # Characterisation of the current node classes (see the class docstring).
        e1, e2, e3 = Expression("a == 1"), Expression("a == 2"), Expression("a == 3")
        assert e1.sum_with(e2).to_json() == ["a == 1", "a == 2"]
        assert e1.sum_with(e2).sum_with(e3).to_json() == ["a == 3", "a == 1", "a == 2"]
        assert PolicySet("y").sum_with(PolicySet("x")).to_json() == ["x", "y"]
        assert PolicySet("y").sum_with(PolicyDict({"x": e1})).to_json() == {
            "x": "a == 1",
            "y": True,
        }
        assert PolicyDict({"x": e1}).sum_with(PolicyDict({"x": e2})).to_json() == {
            "x": ["a == 1", "a == 2"]
        }

    @pytest.mark.parametrize(
        "other, other_contexts, master_json",
        [
            (
                Expression("a == 2"),
                set(),
                {"expressions": ["a == 1", "a == 2"], "policy_dict": {"w": True}},
            ),
            (
                ExpressionList(Expression("a == 2"), Operator({"operator": "istrue"})),
                set(),
                None,  # Operator.to_json is broken (#28).
            ),
            (
                PolicySet("x"),
                {"x"},
                {"expressions": "a == 1", "policy_dict": {"w": True, "x": True}},
            ),
            (
                PolicyDict({"y": Expression("a == 2")}),
                {"y"},
                {"expressions": "a == 1", "policy_dict": {"w": True, "y": "a == 2"}},
            ),
            (
                CompoundPolicy(
                    policy_dict=PolicyDict({"z": POLICY_TRUE}),
                    expressions=ExpressionList(Expression("a == 2")),
                ),
                {"z"},
                None,  # RecursionError in 0.9.1.
            ),
            (
                CompoundPolicy(expressions=Expression("a == 2")),
                set(),
                None,  # RecursionError in 0.9.1.
            ),
        ],
        ids=["expression", "list", "set", "dict", "compound", "lone_compound"],
    )
    @pytest.mark.parametrize(
        "lone",
        [Expression("a == 1"), Operator({"operator": "istrue"})],
        ids=["expression", "operator"],
    )
    @pytest.mark.parametrize("reverse", [False, True])
    def test_compound_policy_with_a_lone_condition_merges(
        self, lone, other, other_contexts, master_json, reverse
    ):
        # Characterisation of the current node classes (see the class docstring).
        # Settings may supply hand-built policies, whose `expressions` may be a lone
        # condition rather than an `ExpressionList`.
        compound = CompoundPolicy(
            policy_dict=PolicyDict({"w": POLICY_TRUE}), expressions=lone
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
        if isinstance(lone, Expression):
            # `to_json` as in 0.9.1 (`master_json`, computed with 0.9.1's policy.py)
            # in either order; `expressions` serialises as given until merged with
            # another condition.
            assert compound.to_json() == {
                "expressions": "a == 1",
                "policy_dict": {"w": True},
            }
            if master_json is not None:
                assert policy.to_json() == master_json
            elif not isinstance(other, ExpressionList):
                policy.to_json()

    @pytest.mark.parametrize("reverse", [False, True])
    def test_compound_policy_with_a_lone_condition_keeps_condition_order(self, reverse):
        # Characterisation of the current node classes (see the class docstring).
        # Expected `to_json` values were computed with 0.9.1's policy.py.
        def hand():
            return CompoundPolicy(
                policy_dict=PolicyDict({"w": POLICY_TRUE}),
                expressions=Expression("a == 1"),
            )

        def ordered(a, b):
            return b.sum_with(a) if reverse else a.sum_with(b)

        merged = ordered(hand(), policy_from_json({"condition": "a == 2"}))
        nested = ordered(PolicyDict({"x": hand()}), policy_from_json([{"x": "a == 2"}]))

        merged_json = {"expressions": ["a == 1", "a == 2"], "policy_dict": {"w": True}}
        assert merged.to_json() == merged_json
        assert nested.to_json() == {"x": merged_json}

    @pytest.mark.parametrize(
        "expressions, other, master_json",
        [
            (
                POLICY_FALSE,
                Expression("a == 2"),
                {"expressions": "a == 2", "policy_dict": {"w": True}},
            ),
            (
                POLICY_FALSE,
                ExpressionList(Expression("a == 2"), Expression("a == 3")),
                {"expressions": ["a == 2", "a == 3"], "policy_dict": {"w": True}},
            ),
            (
                POLICY_TRUE,
                Expression("a == 2"),
                {"expressions": True, "policy_dict": {"w": True}},
            ),
            (
                POLICY_TRUE,
                ExpressionList(Expression("a == 2"), Expression("a == 3")),
                {"expressions": True, "policy_dict": {"w": True}},
            ),
            *[
                (
                    boolean,
                    CompoundPolicy(
                        policy_dict=PolicyDict({"z": POLICY_TRUE}),
                        expressions=ExpressionList(Expression("a == 2")),
                    ),
                    None,  # RecursionError in 0.9.1.
                )
                for boolean in (POLICY_FALSE, POLICY_TRUE)
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
        self, expressions, other, master_json, reverse
    ):
        # Characterisation of the current node classes (see the class docstring).
        # Expected `to_json` values were computed with 0.9.1's policy.py.
        compound = CompoundPolicy(
            policy_dict=PolicyDict({"w": POLICY_TRUE}), expressions=expressions
        )
        a, b = (other, compound) if reverse else (compound, other)

        policy = a.sum_with(b)

        for keys in [(), ("w",), ("z",), ("v",)]:
            for resource in [{"a": 1}, {"a": 2}, {"a": 3}, {}]:
                expected = a.should_allow(*keys, resource=resource) or b.should_allow(
                    *keys, resource=resource
                )
                actual = policy.should_allow(*keys, resource=resource)
                assert actual is expected, (keys, resource)
        if master_json is not None:
            assert policy.to_json() == master_json
        else:
            policy.to_json()

    @pytest.mark.parametrize(
        "policy",
        [
            Expression("a == 1"),
            Operator({"operator": "istrue"}),
            ExpressionList(Expression("a == 1")),
            PolicySet("x"),
            PolicyDict({"x": POLICY_TRUE}),
            CompoundPolicy(expressions=ExpressionList(Expression("a == 1"))),
        ],
        ids=repr,
    )
    @pytest.mark.parametrize("other", [None, object(), {"x": True}], ids=repr)
    def test_merging_an_unsupported_type_raises(self, policy, other):
        # Characterisation of the current node classes (see the class docstring).
        with pytest.raises(NotImplementedError, match="Unsupported type"):
            policy.sum_with(other)
