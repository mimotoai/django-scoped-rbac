import json

from scoped_rbac.policy import Permission, PolicyDict, RootPolicy, policy_from_json

permission_one = Permission(action="GET", resource_type="One")
permission_two = Permission(action="GET", resource_type="Two")
permission_super_user_only = Permission(
    action="NEVER", resource_type="shouldn't matter"
)
permission_action_only = Permission(action="GET", resource_type=None)


def policy_for(context_id, json_policy):
    policy_dict = dict()
    if isinstance(json_policy, str):
        json_policy = json.loads(json_policy)
    return RootPolicy().add_json_policy_for_context(json_policy, context_id)


class TestJsonPolicy:
    def test_empty(self):
        policy = policy_for("a", "{}")
        assert policy.should_allow(permission_one, "a") is False
        assert policy.should_allow(permission_one, "b") is False
        assert policy.should_allow(permission_super_user_only, "a") is False
        policy = policy_for("a", "[]")
        assert policy.should_allow(permission_one, "a") is False
        assert policy.should_allow(permission_one, "b") is False
        assert policy.should_allow(permission_super_user_only, "a") is False

    def test_all_allowed(self):
        policy = policy_for("a", "true")
        assert policy.should_allow(permission_one, "a") is True
        assert policy.should_allow(permission_super_user_only, "a") is True
        assert policy.should_allow(permission_one, "b") is False
        assert policy.should_allow(permission_super_user_only, "b") is False

    def test_string_allowed(self):
        policy = policy_for("a", '"GET"')
        assert policy.should_allow(permission_one, "a") is True
        assert policy.should_allow(permission_super_user_only, "a") is False
        assert policy.should_allow(permission_one, "b") is False
        assert policy.should_allow(permission_super_user_only, "b") is False

    def test_list_allowed(self):
        policy = policy_for("a", '[ "GET", "POST" ]')
        assert policy.should_allow(Permission("GET", "doesn't matter"), "a") is True
        assert policy.should_allow(Permission("POST", "doesn't matter"), "a") is True
        assert policy.should_allow(Permission("DELETE", "doesn't matter"), "a") is False
        assert policy.should_allow(Permission("GET", "doesn't matter"), "b") is False
        assert policy.should_allow(Permission("POST", "doesn't matter"), "b") is False
        assert policy.should_allow(Permission("DELETE", "doesn't matter"), "b") is False

    def test_with_paths(self):
        policy = policy_for(
            "a",
            json.dumps(
                {"GET": True, "PUT": ["ThingOne", "ThingTwo"], "DELETE": "ThingOne"}
            ),
        )

        assert policy.should_allow(Permission("GET", "ThingOne"), "a") is True
        assert policy.should_allow(Permission("GET", "ThingTwo"), "a") is True
        assert policy.should_allow(Permission("GET", "ThingThree"), "a") is True
        assert policy.should_allow(Permission("PUT", "ThingOne"), "a") is True
        assert policy.should_allow(Permission("PUT", "ThingTwo"), "a") is True
        assert policy.should_allow(Permission("PUT", "ThingThree"), "a") is False
        assert policy.should_allow(Permission("DELETE", "ThingOne"), "a") is True
        assert policy.should_allow(Permission("DELETE", "ThingTwo"), "a") is False
        assert policy.should_allow(Permission("DELETE", "ThingThree"), "a") is False
        assert policy.should_allow(permission_super_user_only, "a") is False

        assert policy.should_allow(Permission("GET", "ThingOne"), "b") is False
        assert policy.should_allow(Permission("GET", "ThingTwo"), "b") is False
        assert policy.should_allow(Permission("GET", "ThingThree"), "b") is False
        assert policy.should_allow(Permission("PUT", "ThingOne"), "b") is False
        assert policy.should_allow(Permission("PUT", "ThingTwo"), "b") is False
        assert policy.should_allow(Permission("PUT", "ThingThree"), "b") is False
        assert policy.should_allow(Permission("DELETE", "ThingOne"), "b") is False
        assert policy.should_allow(Permission("DELETE", "ThingTwo"), "b") is False
        assert policy.should_allow(Permission("DELETE", "ThingThree"), "b") is False
        assert policy.should_allow(permission_super_user_only, "b") is False

    def test_expression(self):
        policy = policy_for(
            "a",
            json.dumps(
                {
                    "GET": [
                        {"ThingOne": "content.status == \"ok\""},
                        "ThingTwo",
                        "ThingThree",
                    ]
                }
            ),
        )

        from dataclasses import dataclass

        @dataclass
        class Res:
            id: int
            content: dict

            def to_cel(self):
                return {"id": self.id, "content": self.content}

        thingone = Res(1, {"status": "ok"})
        assert policy.should_allow(Permission("GET", "ThingOne"), "a", thingone) is True


def test_get_contexts_for_ignores_context_conditions():
    """Context-level conditions are ignored for list filtering (fail closed)."""
    policy = RootPolicy().add_policy(policy_from_json({"condition": "true"}))
    policy.add_json_policy_for_context({"GET": ["One"]}, "a")

    assert set(policy.get_contexts_for(permission_one)) == {"a"}
