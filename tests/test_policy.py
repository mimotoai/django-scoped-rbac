from scoped_rbac.policy import (
    Operator,
    Permission,
    PolicyDict,
    PolicySet,
    POLICY_TRUE,
    POLICY_FALSE,
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
    from scoped_rbac.conf import register_operator
    def example_operator(resource, configuration):
        print(resource)
        return resource == True
    register_operator("istrue", example_operator)
    operator = Operator({"operator": "istrue"})
    assert operator.should_allow(resource=False) is False
    assert operator.should_allow(resource=42) is False
    assert operator.should_allow(resource=True) is True