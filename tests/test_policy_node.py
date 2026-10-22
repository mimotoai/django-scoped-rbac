"""`PolicyNode`: the one normalised, immutable policy node, its merge (`sum_with`)
and its three-valued evaluation (GitLab issue #28)."""

import pytest

from scoped_rbac import conf, policy
from scoped_rbac.policy import (
    POLICY_FALSE,
    POLICY_TRUE,
    CompoundPolicy,
    ConditionResult,
    Decision,
    Explanation,
    Expression,
    ExpressionList,
    Operator,
    Permission,
    PolicyDict,
    PolicyFalse,
    PolicyNode,
    PolicySet,
    PolicyTrue,
    RootPolicy,
    policy_from_json,
)

ALLOWED, DENIED, UNDETERMINED = (
    Decision.ALLOWED,
    Decision.DENIED,
    Decision.UNDETERMINED,
)
A1, A2, A3 = Expression("a == 1"), Expression("a == 2"), Expression("a == 3")
ISTRUE = Operator({"operator": "istrue"})


@pytest.fixture
def recording_operators(monkeypatch):
    """Operators that record each call: `allow`, `deny`, `unknown` (returns None)
    and `boom` (raises). Returns the list of called operator names."""
    calls = []

    def recording(name, result):
        def operator(resource, configuration):
            calls.append(name)
            if isinstance(result, Exception):
                raise result
            return result

        return operator

    registered = {
        "allow": recording("allow", True),
        "deny": recording("deny", False),
        "unknown": recording("unknown", None),
        "boom": recording("boom", ZeroDivisionError("boom")),
        "one": recording("one", 1),
        "empty": recording("empty", []),
    }
    monkeypatch.setattr(policy, "operators", lambda: registered)
    return calls


def op(name):
    return Operator({"operator": name})


def node(*conditions, allow_all=False, **children):
    return PolicyNode(allow_all=allow_all, children=children, conditions=conditions)


class TestNode:
    def test_constants(self):
        assert POLICY_TRUE == PolicyNode(allow_all=True)
        assert POLICY_FALSE == PolicyNode()
        assert POLICY_TRUE.children == {} and POLICY_TRUE.conditions == ()

    def test_is_immutable(self):
        children = {"x": POLICY_TRUE}
        n = PolicyNode(children=children, conditions=[A1])

        children["y"] = POLICY_TRUE
        assert set(n.children) == {"x"}
        with pytest.raises(TypeError):
            n.children["z"] = POLICY_TRUE
        for attribute in ("allow_all", "children", "conditions"):
            with pytest.raises(AttributeError):
                setattr(n, attribute, None)
            with pytest.raises(AttributeError):
                delattr(n, attribute)
        assert n.conditions == (A1,)

    def test_allow_all_drops_what_it_subsumes(self):
        assert PolicyNode(True, {"x": POLICY_FALSE}, [A1]) == POLICY_TRUE

    def test_conditions_and_children_are_normalised(self):
        n = PolicyNode(children={"x": A1}, conditions=[A1, A2, A1])

        assert n.children["x"] == PolicyNode(conditions=[A1])
        assert n.conditions == (A1, A2)

    def test_non_policy_children_and_conditions_are_rejected(self):
        with pytest.raises(NotImplementedError, match="Unsupported type"):
            PolicyNode(children={"x": True})
        with pytest.raises(TypeError):
            PolicyNode(conditions=[POLICY_TRUE])

    def test_equality_and_hash(self):
        assert node(A1, x=node(A2)) == node(A1, x=node(A2))
        assert hash(node(A1, x=node(A2))) == hash(node(A1, x=node(A2)))
        assert node(A1) != node(A2)
        assert POLICY_TRUE != True and POLICY_FALSE != {}
        assert node(A1, A2) != node(A2, A1)
        assert Expression("a == 1") == A1 and hash(Expression("a == 1")) == hash(A1)
        assert Operator({"operator": "istrue"}) == ISTRUE
        assert ISTRUE != Operator({"operator": "istrue", "x": 1})
        assert A1 != Operator({"operator": "a == 1"})

    def test_to_json_round_trips(self):
        n = node(
            A1,
            Expression("a == 2", message="m"),
            ISTRUE,
            x=node(y=POLICY_TRUE),
            z=POLICY_FALSE,
        )

        assert POLICY_TRUE.to_json() is True
        assert POLICY_FALSE.to_json() is False
        assert n.to_json() == {
            "children": {"x": {"children": {"y": True}}, "z": False},
            "conditions": [
                {"condition": "a == 1"},
                {"condition": "a == 2", "message": "m"},
                {"condition": {"operator": "istrue"}},
            ],
        }
        assert PolicyNode.from_json(n.to_json()) == n
        assert PolicyNode.from_json(True) is POLICY_TRUE
        assert PolicyNode.from_json(False) is POLICY_FALSE


class TestConditionJson:
    @pytest.mark.parametrize(
        "condition, json_condition",
        [
            (A1, {"condition": "a == 1"}),
            (Expression("a == 1", "m"), {"condition": "a == 1", "message": "m"}),
            (ISTRUE, {"condition": {"operator": "istrue"}}),
            (
                Operator({"operator": "istrue", "n": 1}, message="m"),
                {"condition": {"operator": "istrue", "n": 1}, "message": "m"},
            ),
        ],
        ids=repr,
    )
    def test_round_trip(self, condition, json_condition):
        assert condition.to_json() == json_condition
        assert type(condition).from_json(json_condition) == condition

    def test_from_json_accepts_the_bare_value(self):
        assert Expression.from_json("a == 1") == A1
        assert Operator.from_json({"operator": "istrue"}) == ISTRUE
        with pytest.raises(ValueError, match="Invalid condition"):
            Expression.from_json(42)
        with pytest.raises(ValueError, match="Invalid condition"):
            Operator.from_json("istrue")


class TestMerge:
    def test_allow_all_is_ored(self):
        assert POLICY_TRUE.sum_with(node(A1)) is POLICY_TRUE
        assert node(A1).sum_with(POLICY_TRUE) is POLICY_TRUE
        assert POLICY_FALSE.sum_with(POLICY_FALSE) is POLICY_FALSE

    def test_children_merge_key_wise_and_conditions_concatenate_in_order(self):
        left = node(A1, x=node(A2), y=POLICY_TRUE)
        right = node(A3, A1, x=node(ISTRUE), z=node(A1))

        merged = left.sum_with(right)

        assert merged == node(A1, A3, x=node(A2, ISTRUE), y=POLICY_TRUE, z=node(A1))
        assert right.sum_with(left) == node(
            A3, A1, x=node(ISTRUE, A2), y=POLICY_TRUE, z=node(A1)
        )

    def test_same_condition_with_another_message_is_not_a_duplicate(self):
        merged = node(Expression("a == 1", message="m")).sum_with(node(A1))

        assert merged.conditions == (Expression("a == 1", message="m"), A1)

    def test_operands_are_unchanged(self):
        left, right = node(A1, x=node(A2)), node(A3, x=node(A1), y=POLICY_TRUE)
        before = (left.to_json(), right.to_json())

        left.sum_with(right)

        assert (left.to_json(), right.to_json()) == before

    def test_merging_with_empty_returns_the_operand(self):
        n = node(A1)
        assert n.sum_with(POLICY_FALSE) is n
        assert POLICY_FALSE.sum_with(n) is n

    @pytest.mark.parametrize("condition", [A1, ISTRUE], ids=repr)
    def test_a_lone_condition_merges_as_a_node(self, condition):
        assert condition.sum_with(node(x=POLICY_TRUE)) == node(condition, x=POLICY_TRUE)
        assert node(x=POLICY_TRUE).sum_with(condition) == node(condition, x=POLICY_TRUE)
        assert condition.sum_with(A2) == node(condition, A2)

    @pytest.mark.parametrize("other", [None, object(), {"x": True}], ids=repr)
    @pytest.mark.parametrize("policy_", [A1, ISTRUE, node(x=POLICY_TRUE)], ids=repr)
    def test_merging_an_unsupported_type_raises(self, policy_, other):
        with pytest.raises(NotImplementedError, match="Unsupported type"):
            policy_.sum_with(other)


class TestEvaluate:
    def test_allow_all(self):
        assert POLICY_TRUE.evaluate() is ALLOWED
        assert POLICY_TRUE.evaluate("x", "y", resource={}) is ALLOWED
        assert POLICY_FALSE.evaluate("x") is DENIED

    def test_children_follow_the_keys(self):
        n = node(x=node(y=POLICY_TRUE))

        assert n.evaluate("x", "y") is ALLOWED
        assert n.evaluate("x", "y", "z") is ALLOWED
        assert n.evaluate("x") is DENIED
        assert n.evaluate("x", "z") is DENIED
        assert n.evaluate() is DENIED

    @pytest.mark.parametrize(
        "resource, expected",
        [
            ({"a": 1}, ALLOWED),
            ({"a": 2}, DENIED),
            ({}, UNDETERMINED),
            (None, UNDETERMINED),
            # CEL equality of different types is false, not an error.
            ({"a": "1"}, DENIED),
        ],
    )
    def test_cel_condition(self, resource, expected):
        assert node(A1).evaluate("x", resource=resource) is expected
        assert A1.evaluate("x", resource=resource) is expected
        assert node(A1).should_allow("x", resource=resource) is (expected is ALLOWED)

    def test_constant_cel_condition_needs_no_resource(self):
        assert node(Expression("true")).evaluate() is ALLOWED
        assert node(Expression("false")).evaluate() is DENIED
        assert node(Expression("1 + 1")).evaluate() is UNDETERMINED

    def test_resource_to_cel(self):
        class Resource:
            def to_cel(self):
                return {"a": 1}

        assert A1.evaluate(resource=Resource()) is ALLOWED

    @pytest.mark.parametrize(
        "name, expected",
        [
            ("allow", ALLOWED),
            ("one", ALLOWED),
            ("deny", DENIED),
            ("empty", DENIED),
            ("unknown", UNDETERMINED),
        ],
    )
    def test_operator_condition(self, recording_operators, name, expected):
        assert op(name).evaluate(resource={}) is expected
        assert node(op(name)).evaluate("x") is expected
        assert node(op(name)).should_allow("x") is (expected is ALLOWED)

    def test_kleene_or(self, recording_operators):
        assert node(op("deny"), op("unknown")).evaluate() is UNDETERMINED
        assert node(op("unknown"), op("deny")).evaluate() is UNDETERMINED
        assert node(op("unknown"), op("allow")).evaluate() is ALLOWED
        assert node(op("deny"), op("deny")).evaluate() is DENIED
        assert node(op("deny"), x=node(op("unknown"))).evaluate("x") is UNDETERMINED
        assert node(op("unknown"), x=node(op("allow"))).evaluate("x") is ALLOWED

    def test_children_are_evaluated_before_conditions_and_allow_stops(
        self, recording_operators
    ):
        n = node(op("allow"), op("boom"), x=node(op("unknown"), y=node(op("deny"))))

        assert n.evaluate("x", "y") is ALLOWED
        assert recording_operators == ["deny", "unknown", "allow"]

        recording_operators.clear()
        with pytest.raises(ZeroDivisionError):
            node(op("deny"), op("boom")).evaluate()
        with pytest.raises(ZeroDivisionError):
            node(op("deny"), op("boom")).should_allow()
        assert recording_operators == ["deny", "boom", "deny", "boom"]

    def test_errors_master_raised_still_raise(self):
        unregistered = node(Operator({"operator": "no-such-operator"}))
        for evaluate in (node(A1).evaluate, node(A1).should_allow):
            with pytest.raises(TypeError, match="must be a mapping"):
                evaluate("x", resource=["not", "a", "mapping"])
        for evaluate in (unregistered.evaluate, unregistered.should_allow):
            with pytest.raises(TypeError):
                evaluate("x", resource={})


class TestRootPolicy:
    def test_evaluate_and_should_allow(self, recording_operators):
        root = RootPolicy().add_json_policy_for_context(
            {"GET": {"Thing": {"condition": {"operator": "unknown"}}, "Other": True}},
            "ctx",
        )

        assert root.evaluate(Permission("GET", "Other"), "ctx") is ALLOWED
        assert root.evaluate(Permission("GET", "Thing"), "ctx") is UNDETERMINED
        assert root.evaluate(Permission("GET", "Thing"), "elsewhere") is DENIED
        assert root.should_allow(Permission("GET", "Thing"), "ctx") is False
        assert root.should_allow(Permission("GET", "Other"), "ctx") is True

    def test_policy_is_a_node(self):
        root = RootPolicy().add_json_policy_for_context({"condition": "a == 1"}, "c")

        assert root.policy == node(c=node(A1))


class TestPolicyFromJson:
    @pytest.mark.parametrize(
        "json_policy, expected",
        [
            (True, POLICY_TRUE),
            (False, POLICY_FALSE),
            ("x", node(x=POLICY_TRUE)),
            (["x", "y"], node(x=POLICY_TRUE, y=POLICY_TRUE)),
            ({"condition": "a == 1"}, node(A1)),
            ({"condition": {"operator": "istrue"}}, node(ISTRUE)),
            ([{"x": "a == 1"}, "y"], node(x=node(A1), y=POLICY_TRUE)),
            (
                {"x": {"y": {"condition": "a == 1"}, "z": True}},
                node(x=node(y=node(A1), z=POLICY_TRUE)),
            ),
            ({"x": {"y": [{"operator": "istrue"}]}}, node(x=node(y=node(ISTRUE)))),
            ({"x": {"y": {"z": "a == 1"}}}, node(x=node(y=node(z=node(A1))))),
        ],
        ids=repr,
    )
    def test_builds_nodes(self, json_policy, expected):
        assert policy_from_json(json_policy) == expected


class TestDeprecatedConstructors:
    def test_policy_true_and_false(self):
        with pytest.deprecated_call():
            assert PolicyTrue() is POLICY_TRUE
        with pytest.deprecated_call():
            assert PolicyFalse() is POLICY_FALSE

    def test_policy_set(self):
        with pytest.deprecated_call():
            assert PolicySet("x", "y") == node(x=POLICY_TRUE, y=POLICY_TRUE)
        with pytest.deprecated_call():
            assert PolicySet() == POLICY_FALSE

    def test_policy_dict(self):
        with pytest.deprecated_call():
            built = PolicyDict({"x": POLICY_TRUE, "y": A1})
        assert built == node(x=POLICY_TRUE, y=node(A1))

    def test_expression_list(self):
        with pytest.deprecated_call():
            assert ExpressionList(A1, ISTRUE, A1) == node(A1, ISTRUE)

    def test_compound_policy(self):
        with pytest.deprecated_call():
            built = CompoundPolicy(
                policy_dict=node(x=node(A2)),
                policy_set=node(y=POLICY_TRUE),
                expressions=A1,
            )
        assert built == node(A1, x=node(A2), y=POLICY_TRUE)
        with pytest.deprecated_call():
            assert CompoundPolicy() == POLICY_FALSE
        with pytest.deprecated_call():
            assert CompoundPolicy(node(x=POLICY_TRUE), None, POLICY_TRUE) == (
                POLICY_TRUE
            )


def test_a_lone_condition_settings_default_is_a_node(monkeypatch):
    monkeypatch.setattr(
        conf, "RESOLVED_SETTINGS", conf.Settings([{"POLICY_FOR_STAFF": A1}])
    )

    assert conf.policy_for_staff() == node(A1)


class TestMessages:
    """A condition dict may carry a "message" describing the condition."""

    M1 = Expression("a == 1", message="a must be 1")

    @pytest.mark.parametrize(
        "json_policy, expected",
        [
            ({"condition": "a == 1", "message": "a must be 1"}, node(M1)),
            (
                {"condition": {"operator": "istrue", "n": 2}, "message": "m"},
                node(Operator({"operator": "istrue", "n": 2}, message="m")),
            ),
            (
                {"GET": {"Thing": {"condition": "a == 1", "message": "a must be 1"}}},
                node(GET=node(Thing=node(M1))),
            ),
            # An action condition in the list form may be a condition dict, at the
            # top level and under an action.
            (
                [{"DELETE": {"condition": "a == 1", "message": "a must be 1"}}, "GET"],
                node(DELETE=node(M1), GET=POLICY_TRUE),
            ),
            ([{"DELETE": {"condition": "a == 1"}}], node(DELETE=node(A1))),
            (
                {"GET": [{"Thing": {"condition": "a == 1", "message": "a must be 1"}}]},
                node(GET=node(Thing=node(M1))),
            ),
            # Still a CEL string, as before.
            ([{"DELETE": "a == 1"}], node(DELETE=node(A1))),
        ],
        ids=repr,
    )
    def test_parsed(self, json_policy, expected):
        assert policy_from_json(json_policy) == expected

    def test_action_condition_dict_is_evaluated(self):
        policy = policy_from_json([{"DELETE": {"condition": "a == 1", "message": "m"}}])

        assert policy.evaluate("DELETE", "Thing", resource={"a": 1}) is ALLOWED
        assert policy.evaluate("DELETE", "Thing", resource={"a": 2}) is DENIED

    def test_messages_travel_through_merges(self):
        with_message = policy_from_json(
            [{"DELETE": {"condition": "a == 1", "message": "a must be 1"}}]
        )
        other_message = policy_from_json(
            [{"DELETE": {"condition": "a == 1", "message": "other"}}]
        )
        without = policy_from_json([{"DELETE": "a == 1"}])

        merged = with_message.sum_with(other_message).sum_with(without)

        assert merged.children["DELETE"].conditions == (
            self.M1,
            Expression("a == 1", message="other"),
            A1,
        )
        assert with_message.sum_with(with_message) == with_message
        root = RootPolicy().add_policy_for_context(merged, "ctx")
        assert root.to_json()["ctx"]["DELETE"]["*"] == {
            "conditions": [
                {"condition": "a == 1", "message": "a must be 1"},
                {"condition": "a == 1", "message": "other"},
                {"condition": "a == 1"},
            ]
        }


class TestWildcard:
    """A "*" key matches any key at its level."""

    def test_matches_any_key(self):
        n = node(**{"*": node(y=POLICY_TRUE)})

        assert n.evaluate("x", "y") is ALLOWED
        assert n.evaluate("*", "y") is ALLOWED
        assert n.evaluate("x", "z") is DENIED
        assert n.evaluate("x") is DENIED
        assert n.evaluate() is DENIED

    def test_specific_key_then_wildcard_then_conditions(self, recording_operators):
        n = node(op("unknown"), x=node(op("deny")), **{"*": node(op("unknown"))})

        assert n.evaluate("x") is UNDETERMINED
        assert recording_operators == ["deny", "unknown", "unknown"]

        recording_operators.clear()
        assert n.evaluate("*") is UNDETERMINED
        assert recording_operators == ["unknown", "unknown"]

    @pytest.mark.parametrize(
        "definition",
        [["*"], {"*": True}, {"*": ["*"]}, {"*": {"*": True}}, [{"*": "true"}]],
        ids=repr,
    )
    def test_in_a_role_is_like_true(self, definition):
        root = RootPolicy().add_json_policy_for_context(definition, "ctx")

        for permission in (Permission("GET", "Thing"), Permission("PUT", None)):
            assert root.evaluate(permission, "ctx") is ALLOWED
            assert root.evaluate(permission, "other") is DENIED

    def test_any_action_on_a_resource_type(self):
        root = RootPolicy().add_json_policy_for_context({"*": ["Thing"]}, "ctx")

        assert root.should_allow(Permission("GET", "Thing"), "ctx") is True
        assert root.should_allow(Permission("DELETE", "Thing"), "ctx") is True
        assert root.should_allow(Permission("GET", "Other"), "ctx") is False

    def test_any_context_in_a_settings_default(self):
        root = RootPolicy().add_policy(policy_from_json({"*": {"GET": ["Thing"]}}))

        assert root.should_allow(Permission("GET", "Thing"), "ctx1") is True
        assert root.should_allow(Permission("GET", "Thing"), "__SOME_CONTEXT__")
        assert root.should_allow(Permission("PUT", "Thing"), "ctx1") is False


class TestExplain:
    """`explain` gives the decision and each condition evaluated for it."""

    def test_lists_the_conditions_evaluated_in_order(self, recording_operators):
        deny = Operator({"operator": "deny"}, message="never")
        n = node(
            op("unknown"),
            x=node(A1, y=node(deny)),
            **{"*": node(Expression("a == 2", message="a must be 2"))},
        )

        explanation = n.explain("x", "y", resource={"a": 3})

        assert explanation == Explanation(
            UNDETERMINED,
            (
                ConditionResult(
                    {"condition": {"operator": "deny"}, "message": "never"},
                    DENIED,
                    "never",
                ),
                ConditionResult({"condition": "a == 1"}, DENIED, None),
                ConditionResult(
                    {"condition": "a == 2", "message": "a must be 2"},
                    DENIED,
                    "a must be 2",
                ),
                ConditionResult(
                    {"condition": {"operator": "unknown"}}, UNDETERMINED, None
                ),
            ),
        )
        assert explanation.decision is n.evaluate("x", "y", resource={"a": 3})
        assert explanation.to_json() == {
            "decision": "undetermined",
            "conditions": [
                {
                    "condition": {"operator": "deny"},
                    "message": "never",
                    "decision": "denied",
                },
                {"condition": "a == 1", "decision": "denied"},
                {"condition": "a == 2", "message": "a must be 2", "decision": "denied"},
                {"condition": {"operator": "unknown"}, "decision": "undetermined"},
            ],
        }

    def test_stops_at_the_first_allowed(self, recording_operators):
        n = node(op("boom"), x=node(A1, op("allow")))

        explanation = n.explain("x", resource={"a": 2})

        assert explanation.decision is ALLOWED
        assert [c.condition for c in explanation.conditions] == [
            {"condition": "a == 1"},
            {"condition": {"operator": "allow"}},
        ]
        assert [c.decision for c in explanation.conditions] == [DENIED, ALLOWED]

    def test_lists_a_condition_evaluated_twice_once(self):
        n = node(A1, x=node(A1, Expression("a == 1", message="m")))

        explanation = n.explain("x", resource={})

        assert explanation.conditions == (
            ConditionResult({"condition": "a == 1"}, UNDETERMINED, None),
            ConditionResult({"condition": "a == 1", "message": "m"}, UNDETERMINED, "m"),
        )

    def test_without_conditions(self):
        assert POLICY_TRUE.explain("x") == Explanation(ALLOWED, ())
        assert POLICY_FALSE.explain("x") == Explanation(DENIED, ())
        assert A1.explain(resource={"a": 1}) == Explanation(
            ALLOWED, (ConditionResult({"condition": "a == 1"}, ALLOWED, None),)
        )

    def test_raises_as_evaluate_does(self, recording_operators):
        with pytest.raises(ZeroDivisionError):
            node(op("boom")).explain()

    def test_root_policy(self):
        root = RootPolicy().add_json_policy_for_context(
            [{"DELETE": {"condition": "a == 1", "message": "a must be 1"}}], "ctx"
        )

        explanation = root.explain(Permission("DELETE", "Thing"), "ctx", {"a": 2})

        assert explanation == Explanation(
            DENIED,
            (
                ConditionResult(
                    {"condition": "a == 1", "message": "a must be 1"},
                    DENIED,
                    "a must be 1",
                ),
            ),
        )
        assert root.explain(Permission("DELETE", "Thing"), "other") == Explanation(
            DENIED, ()
        )
