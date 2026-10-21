from scoped_rbac.policy import policy_from_json
from scoped_rbac.rbac_contexts import DEFAULT_CONTEXT


def policy_for_unauthenticated():
    return policy_from_json(
        {
            DEFAULT_CONTEXT: {
                "http.GET": [
                    "rbac.ExampleAccessControlledModel",
                ],
                "http.POST": [
                    "rbac.ExampleAccessControlledModel",
                ],
            }
        }
    )


def policy_for_staff():
    return policy_from_json(
        {
            DEFAULT_CONTEXT: {
                "http.GET": [
                    "rbac.ExampleAccessControlledModel",
                    "rbac.ExampleAccessControlledModel/list",
                ],
            }
        }
    )
