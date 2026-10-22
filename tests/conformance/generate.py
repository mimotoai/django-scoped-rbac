"""Generate the conformance fixtures in ``fixtures/`` with the Python policy engine.

Run from the repository root after changing a case or the engine:

    uv run python tests/conformance/generate.py

``tests/test_conformance.py`` fails if the checked-in fixtures differ from what this
generates. See README.md for the fixture format.
"""

import itertools
import json
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SOME_CONTEXT = "__SOME_CONTEXT__"

A1 = {"condition": "a == 1"}
A2 = {"condition": "a == 2"}
ISTRUE = {"condition": {"operator": "istrue"}}

# The policy pool of tests/test_policy_merge_properties.py, as the JSON policies
# merged (in order) to build each.
POOL = {
    "true": [True],
    "false": [False],
    "condition_a1": [A1],
    "condition_a2": [A2],
    "operator": [ISTRUE],
    "set_empty": [[]],
    "set_x": ["x"],
    "set_yz": [["y", "z"]],
    "dict_empty": [{}],
    "dict_true_and_set": [{"x": True, "z": ["y"]}],
    "dict_false_and_empty": [{"x": False, "y": []}],
    "dict_x_condition": [[{"x": "a == 1"}]],
    "dict_x_set": [{"x": ["y"]}],
    "dict_xy_condition": [{"x": [{"y": "a == 1"}]}],
    "nested_3_levels": [
        {"x": {"y": "z", "z": {"x": "a == 2", "y": True}}, "y": ["x", "z"]}
    ],
    "nested_operator": [{"y": {"x": [{"operator": "istrue"}], "z": True}}],
    "conditions_2": [A1, A2],
    "condition_and_operator": [A2, ISTRUE],
    "condition_or_dict": [A2, {"x": {"y": "x"}}],
    "operator_or_set": [ISTRUE, ["y"]],
    "nested_condition_or_set": [{"x": {"y": A1}}, {"x": {"y": ["z"]}}],
    "nested_conditions": [{"y": {"x": A1}}, {"y": {"x": ISTRUE}}],
    "operator_and_conditions": [ISTRUE, A1, A2],
    "ternary_condition": [{"condition": "a > 1 ? a == 3 : false"}],
    "action_condition_or_set": [[{"x": "a == 1"}], {"x": ["y"]}],
    "resource_operator": [{"x": {"y": ISTRUE}, "y": {"x": True}}],
    "resource_condition_and_operator": [{"x": {"y": A2}}, {"x": {"y": ISTRUE}}],
    "resource_operator_or_set": [{"x": {"y": ISTRUE}}, {"x": {"y": ["z"]}}],
}

RESOURCES = [{"a": 1}, {"a": 2}, {"a": 3}, {}, None]


def grid(contexts, actions, resource_types, resources=RESOURCES):
    """Probes for every combination: (context, action, resource type, resource)."""
    return list(itertools.product(contexts, actions, resource_types, resources))


POOL_KEYS = ["x", "y", "z"]
POOL_RESOURCES = [{"a": 1}, {"a": 2}, {"a": 3}, {}]


def pool_cases():
    for name, json_policies in POOL.items():
        yield {
            "name": f"default_{name}",
            "defaults": json_policies,
            "probes": grid(
                ["x", "y", SOME_CONTEXT], POOL_KEYS, POOL_KEYS, POOL_RESOURCES
            ),
        }
        yield {
            "name": f"role_{name}",
            "assignments": [{"definition": d, "context": "x"} for d in json_policies],
            "probes": grid(["x", SOME_CONTEXT], POOL_KEYS, POOL_KEYS, POOL_RESOURCES),
        }


def role(definition, context):
    return {"definition": definition, "context": context}


GET, PUT, DELETE = "http.GET", "http.PUT", "http.DELETE"
THING, OTHER = "app.Thing", "app.Other"
THING_PROBES = grid(["c1", "c2", SOME_CONTEXT], [GET, DELETE], [THING, OTHER])

GRAMMAR_CASES = [
    {"name": "nothing", "assignments": [], "probes": THING_PROBES[:5]},
    {
        "name": "role_true",
        "description": "A role that allows everything in its context.",
        "assignments": [role(True, "c1")],
        "probes": THING_PROBES,
    },
    {
        "name": "role_action_names",
        "assignments": [role(GET, "c1"), role([PUT, DELETE], "c2")],
        "probes": grid(["c1", "c2"], [GET, PUT, DELETE], [THING], [{}]),
    },
    {
        "name": "role_action_and_resource_types",
        "assignments": [
            role({GET: True, PUT: [THING, OTHER], DELETE: THING}, "c1"),
        ],
        "probes": grid(["c1", "c2"], [GET, PUT, DELETE], [THING, OTHER], [{}]),
    },
    {
        "name": "role_conditions_at_each_level",
        "assignments": [
            role({"condition": "a == 1"}, "c1"),
            role([{DELETE: "a == 2"}, GET], "c2"),
            role({PUT: [{THING: "a == 3"}]}, "c2"),
            role({GET: {OTHER: {"condition": "a > 1"}}}, "c3"),
        ],
        "probes": grid(["c1", "c2", "c3"], [GET, PUT, DELETE], [THING, OTHER]),
    },
    {
        "name": "role_resource_type_dict",
        "assignments": [role({GET: {THING: {"x": True, "y": "a == 1"}}}, "c1")],
        "probes": grid(["c1"], [GET], [THING, OTHER]),
    },
    {
        "name": "defaults_name_contexts",
        "description": "Settings defaults start at the context level.",
        "defaults": [{"c1": {GET: [THING]}, "c2": True}, "c3"],
        "probes": grid(["c1", "c2", "c3", "c4", SOME_CONTEXT], [GET], [THING, OTHER]),
    },
    {
        "name": "defaults_and_roles",
        "defaults": [{"condition": "a == 1"}, {"c1": {GET: [OTHER]}}],
        "assignments": [role({DELETE: [THING]}, "c2")],
        "probes": THING_PROBES,
    },
    {
        "name": "allow_all_default",
        "description": "As for a superuser.",
        "defaults": [True],
        "assignments": [role({GET: [THING]}, "c1")],
        "probes": THING_PROBES[:10],
    },
]

WILDCARD_CASES = [
    {
        "name": "any_action",
        "assignments": [role(["*"], "c1"), role({"*": [THING]}, "c2")],
        "probes": THING_PROBES,
    },
    {
        "name": "any_resource_type",
        "assignments": [role({GET: {"*": True}}, "c1"), role({DELETE: ["*"]}, "c2")],
        "probes": THING_PROBES,
    },
    {
        "name": "any_context_default",
        "description": 'A "*" context is not copied to __SOME_CONTEXT__, which it '
        "already matches.",
        "defaults": [{"*": {GET: [THING]}, "c1": {DELETE: [THING]}}],
        "probes": THING_PROBES + grid(["*"], [GET, DELETE], [THING], [{}]),
    },
    {
        "name": "specific_key_then_any",
        "description": 'The specific key is evaluated before "*", at each level.',
        "assignments": [
            role(
                {GET: {THING: {"condition": "a == 1"}, "*": {"condition": "a == 2"}}},
                "c1",
            ),
            role([{"*": "a == 3"}], "c1"),
        ],
        "probes": grid(["c1"], [GET, DELETE], [THING, OTHER]),
    },
    {
        "name": "literal_star_keys",
        "description": 'A request whose key is "*" matches the "*" key once.',
        "assignments": [role({"*": {"*": {"condition": "a == 1"}}}, "*")],
        "probes": grid(["*", "c1"], ["*", GET], ["*", THING], [{"a": 1}, {}]),
    },
]

MESSAGE = "a must be 1"
MESSAGE_CASES = [
    {
        "name": "messages_at_each_level",
        "assignments": [
            role({"condition": "a == 1", "message": MESSAGE}, "c1"),
            role([{DELETE: {"condition": "a == 2", "message": "a must be 2"}}], "c2"),
            role(
                {GET: {THING: {"condition": "a == 3", "message": "a must be 3"}}},
                "c2",
            ),
            role(
                {
                    GET: {
                        OTHER: {
                            "condition": {"operator": "a_at_least", "min": 2},
                            "message": "a must be at least 2",
                        }
                    }
                },
                "c3",
            ),
        ],
        "probes": grid(["c1", "c2", "c3"], [GET, DELETE], [THING, OTHER]),
    },
    {
        "name": "same_condition_other_message",
        "description": "The same condition with different messages is kept for each.",
        "assignments": [
            role([{DELETE: {"condition": "a == 1", "message": MESSAGE}}], "c1"),
            role([{DELETE: {"condition": "a == 1", "message": "other"}}], "c1"),
            role([{DELETE: "a == 1"}], "c1"),
            role([{DELETE: {"condition": "a == 1", "message": MESSAGE}}], "c1"),
        ],
        "probes": grid(["c1"], [DELETE], [THING]),
    },
]

OPERATOR_CASES = [
    {
        "name": "istrue",
        "assignments": [role({GET: {THING: ISTRUE}}, "c1")],
        "probes": grid(["c1"], [GET], [THING], [{"a": 3}, {"a": 1}, {}, None, True]),
    },
    {
        "name": "a_at_least",
        "assignments": [
            role(
                {GET: {THING: {"condition": {"operator": "a_at_least", "min": 2}}}},
                "c1",
            ),
            role({PUT: {THING: [{"operator": "a_at_least", "min": 3}]}}, "c1"),
        ],
        "probes": grid(
            ["c1"],
            [GET, PUT],
            [THING],
            [{"a": 1}, {"a": 2}, {"a": 3}, {"a": "x"}, {}, None],
        ),
    },
    {
        "name": "operator_and_cel",
        "assignments": [
            role(
                {GET: {THING: {"condition": {"operator": "a_at_least", "min": 3}}}},
                "c1",
            ),
            role({GET: {THING: {"condition": "a == 1"}}}, "c1"),
        ],
        "probes": grid(
            ["c1"], [GET], [THING], [{"a": 1}, {"a": 2}, {"a": 3}, {}, None]
        ),
    },
]

UNDETERMINED_CASES = [
    {
        "name": "missing_variable_or_resource",
        "assignments": [role({GET: {THING: {"condition": "a == 1"}}}, "c1")],
        "probes": grid(
            ["c1"], [GET], [THING], [{"a": 1}, {"a": 2}, {"b": 1}, {}, None]
        ),
    },
    {
        "name": "missing_field",
        "assignments": [role({GET: {THING: {"condition": "b.c == 'x'"}}}, "c1")],
        "probes": grid(
            ["c1"], [GET], [THING], [{"b": {"c": "x"}}, {"b": {"c": "y"}}, {"b": {}}]
        ),
    },
    {
        "name": "constant_conditions_need_no_resource",
        "assignments": [
            role({GET: {THING: {"condition": "true"}}}, "c1"),
            role({GET: {THING: {"condition": "false"}}}, "c2"),
        ],
        "probes": grid(["c1", "c2"], [GET], [THING], [None, {}]),
    },
    {
        "name": "non_boolean_result",
        "assignments": [role({GET: {THING: {"condition": "1 + 1"}}}, "c1")],
        "probes": grid(["c1"], [GET], [THING], [None, {}]),
    },
    {
        "name": "kleene_or",
        "description": "Undetermined or denied is undetermined; anything or "
        "allowed is allowed.",
        "assignments": [
            role({GET: {THING: {"condition": "a == 1"}}}, "c1"),
            role({GET: {THING: {"condition": "b == 1"}}}, "c1"),
            role(
                {GET: {"*": {"condition": {"operator": "a_at_least", "min": 5}}}}, "c1"
            ),
        ],
        "probes": grid(
            ["c1"], [GET], [THING, OTHER], [{"a": 1}, {"a": 2}, {"b": 1}, {"a": 6}, {}]
        ),
    },
]

MERGING_CASES = [
    {
        "name": "duplicate_conditions",
        "description": "A condition granted twice at one place is kept once; at "
        "different places it is in each, and listed once when evaluated.",
        "defaults": [A1],
        "assignments": [
            role([{DELETE: "a == 1"}], "c1"),
            role([{DELETE: "a == 1"}, {DELETE: "a == 2"}], "c1"),
            role(A1, "c1"),
        ],
        "probes": grid(["c1", "c2"], [DELETE, GET], [THING]),
    },
    {
        "name": "conditions_keep_assignment_order",
        "assignments": [
            role([{DELETE: "a == 2"}], "c1"),
            role([{DELETE: "a == 1"}], "c1"),
        ],
        "probes": grid(["c1"], [DELETE], [THING]),
    },
    {
        "name": "role_in_two_contexts",
        "assignments": [role({GET: [THING]}, "c1"), role({GET: [THING]}, "c2")],
        "probes": THING_PROBES,
    },
    {
        "name": "some_context_copies_context_grants_only",
        "description": "A default's top-level condition is not copied to "
        "__SOME_CONTEXT__ (it applies there already); its context grants are.",
        "defaults": [{"condition": "a == 3"}, {"c1": {GET: {THING: "a == 1"}}}],
        "probes": THING_PROBES,
    },
    {
        "name": "set_of_contexts_default",
        "defaults": [["c1", "c2"]],
        "probes": THING_PROBES[:10],
    },
]

WIRE_CASES = [
    {
        "name": "wire_any_then_specific",
        "wire_input": {"*": {GET: {THING: True}}, "c1": {"*": {OTHER: True}}},
        "probes": THING_PROBES,
    },
    {
        "name": "wire_conditions",
        "wire_input": {
            "*": {"*": {"*": {"conditions": [A1]}}},
            "c1": {
                GET: {
                    THING: {
                        "conditions": [
                            {"condition": "a == 2", "message": "a must be 2"},
                            {"condition": {"operator": "a_at_least", "min": 3}},
                        ]
                    },
                    "*": {"conditions": [ISTRUE]},
                }
            },
        },
        "probes": grid(["c1", "c2"], [GET], [THING, OTHER]),
    },
    {
        "name": "wire_canonical_form",
        "description": "Empty objects and leaves that grant nothing are left out, "
        "and a condition repeated in a leaf is kept once.",
        "wire_input": {
            "c1": {GET: {}},
            "c2": {PUT: {THING: {"conditions": []}}},
            "c3": {GET: {THING: {"conditions": [A1, A2, A1]}}},
        },
        "probes": grid(["c1", "c2", "c3"], [GET, PUT], [THING], [{"a": 1}, {}]),
    },
]

FIXTURE_FILES = {
    "pool.json": (
        "The merge property tests' policy pool, as settings defaults and as roles "
        "in context x.",
        list(pool_cases()),
    ),
    "grammar.json": ("The policy JSON grammar.", GRAMMAR_CASES),
    "wildcards.json": ('The "*" key.', WILDCARD_CASES),
    "messages.json": ("Condition messages.", MESSAGE_CASES),
    "operators.json": ("The fixture operators istrue and a_at_least.", OPERATOR_CASES),
    "undetermined.json": ("Conditions that cannot be decided.", UNDETERMINED_CASES),
    "merging.json": (
        "Merging a user's defaults and roles, and the __SOME_CONTEXT__ copies.",
        MERGING_CASES,
    ),
    "wire.json": ("Policies given in the wire format.", WIRE_CASES),
}


def policy_for(case):
    """The policy of a user with the case's settings defaults and role assignments
    (as `permissions.policy_for` builds it), or of its wire input."""
    from scoped_rbac.permissions import sum_policies
    from scoped_rbac.policy import RootPolicy, policy_from_json

    if "wire_input" in case:
        return RootPolicy.from_json(case["wire_input"])
    policy = RootPolicy()
    for default in case.get("defaults", []):
        sum_policies(policy, policy_from_json(default))
    for assignment in case.get("assignments", []):
        definition = policy_from_json(assignment["definition"])
        policy.add_policy_for_context(definition, assignment["context"])
        policy.add_policy_for_context(definition, SOME_CONTEXT)
    return policy


def build_case(spec):
    from scoped_rbac.policy import Permission

    policy = policy_for(spec)
    case = {key: value for key, value in spec.items() if key != "probes"}
    case["wire"] = policy.to_json()
    case["probes"] = []
    for context, action, resource_type, resource in spec["probes"]:
        explanation = policy.explain(
            Permission(action, resource_type), context, resource
        ).to_json()
        case["probes"].append(
            {
                "context": context,
                "action": action,
                "resource_type": resource_type,
                "resource": resource,
                "expected": explanation["decision"],
                "conditions": explanation["conditions"],
            }
        )
    return case


def dumps(value, indent=""):
    """JSON with one probe per line."""
    inner = indent + "  "
    if isinstance(value, dict) and value:
        items = []
        for key, item in value.items():
            if key == "probes":
                rendered = (
                    "[\n"
                    + ",\n".join(inner + "  " + json.dumps(p) for p in item)
                    + f"\n{inner}]"
                    if item
                    else "[]"
                )
            else:
                rendered = dumps(item, inner)
            items.append(f"{inner}{json.dumps(key)}: {rendered}")
        return "{\n" + ",\n".join(items) + f"\n{indent}}}"
    if isinstance(value, list) and value:
        return (
            "[\n"
            + ",\n".join(inner + dumps(item, inner) for item in value)
            + f"\n{indent}]"
        )
    return json.dumps(value)


def render():
    """The fixture files: {file name: content}."""
    return {
        file_name: dumps(
            {
                "description": description,
                "cases": [build_case(spec) for spec in specs],
            }
        )
        + "\n"
        for file_name, (description, specs) in FIXTURE_FILES.items()
    }


def configure_django():
    """Settings for running the engine outside the test suite, with the fixture
    operators."""
    import django
    from django.conf import settings

    from tests.conformance.operators import OPERATORS

    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "scoped_rbac",
        ],
        SCOPED_RBAC={"OPERATORS": OPERATORS},
    )
    django.setup()


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    configure_django()
    FIXTURES.mkdir(exist_ok=True)
    rendered = render()
    for stale in set(p.name for p in FIXTURES.glob("*.json")) - set(rendered):
        (FIXTURES / stale).unlink()
    for file_name, content in rendered.items():
        (FIXTURES / file_name).write_text(content)
        print(f"wrote {FIXTURES / file_name}")


if __name__ == "__main__":
    main()
