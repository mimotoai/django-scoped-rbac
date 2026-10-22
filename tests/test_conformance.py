"""The conformance fixtures in tests/conformance (see its README.md), which other
implementations of the policy engine run too: the Python engine matches every
fixture, and the checked-in fixtures are those the generator makes."""

import json
from pathlib import Path

import pytest

from scoped_rbac.permissions import sum_policies
from scoped_rbac.policy import Decision, Permission, RootPolicy, policy_from_json
from scoped_rbac.rbac_contexts import SOME_CONTEXT

from .conformance import generate
from .test_policy_merge_properties import POLICIES as MERGE_POOL

FIXTURES = Path(__file__).parent / "conformance" / "fixtures"


def load_cases():
    for path in sorted(FIXTURES.glob("*.json")):
        for case in json.loads(path.read_text())["cases"]:
            yield f"{path.stem}/{case['name']}", case


CASES = dict(load_cases())


def policy_from_authoring(case):
    """The policy of a user with the case's settings defaults and role assignments,
    built as `permissions.policy_for` builds it."""
    policy = RootPolicy()
    for default in case.get("defaults", []):
        sum_policies(policy, policy_from_json(default))
    for assignment in case.get("assignments", []):
        role = policy_from_json(assignment["definition"])
        policy.add_policy_for_context(role, assignment["context"])
        policy.add_policy_for_context(role, SOME_CONTEXT)
    return policy


def policies_of(case):
    """(description, policy) for each way the case gives its policy, and for its
    expected wire format."""
    if "wire_input" in case:
        yield "wire_input", RootPolicy.from_json(case["wire_input"])
    if "defaults" in case or "assignments" in case:
        yield "authoring", policy_from_authoring(case)
    yield "wire", RootPolicy.from_json(case["wire"])


def test_fixture_files_are_those_generated():
    assert generate.render() == {
        path.name: path.read_text() for path in FIXTURES.glob("*.json")
    }


def test_fixtures_cover_every_decision():
    expected = {
        probe["expected"] for case in CASES.values() for probe in case["probes"]
    }

    assert expected == {decision.value for decision in Decision}
    assert len(CASES) > 50


@pytest.mark.parametrize("name", generate.POOL)
def test_pool_is_the_merge_property_pool(name):
    """The fixtures' pool is the merge property tests' pool."""
    total = policy_from_json(generate.POOL[name][0])
    for json_policy in generate.POOL[name][1:]:
        total = total.sum_with(policy_from_json(json_policy))

    assert total == MERGE_POOL[name][0]()
    assert set(generate.POOL) == set(MERGE_POOL)


@pytest.mark.parametrize("name", CASES)
def test_engine_matches_fixture(name):
    case = CASES[name]
    assert ("wire_input" in case) != ("defaults" in case or "assignments" in case)

    for source, policy in policies_of(case):
        assert policy.to_json() == case["wire"], source
        for probe in case["probes"]:
            permission = Permission(probe["action"], probe["resource_type"])
            context, resource = probe["context"], probe["resource"]

            explanation = policy.explain(permission, context, resource)

            assert explanation.decision.value == probe["expected"], (source, probe)
            assert [c.to_json() for c in explanation.conditions] == probe[
                "conditions"
            ], (source, probe)
            assert (
                policy.evaluate(permission, context, resource).value
                == (probe["expected"])
            )
            assert policy.should_allow(permission, context, resource) is (
                probe["expected"] == "allowed"
            )
