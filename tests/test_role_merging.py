"""A user's roles are merged into one policy by `policy_for` (GitLab issues #2, #3)."""

import pytest
from django.conf import settings
from django.test import override_settings
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from scoped_rbac import conf
from scoped_rbac.conf import policy_for_authenticated, policy_for_staff
from scoped_rbac.permissions import policy_for
from scoped_rbac.policy import Permission, policy_from_json
from scoped_rbac.rbac_contexts import DEFAULT_CONTEXT, SOME_CONTEXT

from .helpers import EXAMPLE, EXAMPLE_URL, assign, client_for, grant, make_role
from .models import ExampleAccessControlledModel

OK = {"status": "ok"}
NOT_OK = {"status": "no"}
CONDITIONAL_ROLES = [
    # A condition on an action, and a condition on the whole context.
    [{"http.GET": "status == 'ok'"}],
    {"condition": "status == 'ok'"},
]


def get(resource_type):
    return Permission("http.GET", resource_type)


def policy_for_user(user):
    request = Request(APIRequestFactory().get("/"))
    request.user = user
    return policy_for(request)


def assign_in_order(user, assignments, reverse):
    for role, rbac_context in reversed(assignments) if reverse else assignments:
        assign(user, role, rbac_context)


@pytest.mark.parametrize("conditional_definition", CONDITIONAL_ROLES)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.django_db
def test_conditional_and_plain_roles_in_different_contexts_grant_the_union(
    user, conditional_definition, reverse
):
    conditional = make_role(conditional_definition)
    plain = make_role({"http.GET": [EXAMPLE]})
    assign_in_order(user, [(conditional, "ctx1"), (plain, "ctx2")], reverse)

    policy = policy_for_user(user)

    # ctx1: only the conditional role, for any resource type.
    assert policy.should_allow(get(EXAMPLE), "ctx1", OK)
    assert policy.should_allow(get("Other"), "ctx1", OK)
    assert not policy.should_allow(get(EXAMPLE), "ctx1", NOT_OK)
    # ctx2: only the plain role.
    assert policy.should_allow(get(EXAMPLE), "ctx2", NOT_OK)
    assert not policy.should_allow(get("Other"), "ctx2", OK)
    # Some context: either role.
    assert policy.should_allow(get(EXAMPLE), SOME_CONTEXT, NOT_OK)
    assert policy.should_allow(get("Other"), SOME_CONTEXT, OK)
    assert not policy.should_allow(get("Other"), SOME_CONTEXT, NOT_OK)
    # Nothing else.
    assert not policy.should_allow(get(EXAMPLE), "ctx3", OK)
    assert not policy.should_allow(Permission("http.PUT", EXAMPLE), "ctx2", OK)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.django_db
def test_requests_by_a_user_with_conditional_and_plain_roles_succeed(user, reverse):
    conditional = make_role([{"http.GET": "status == 'ok'"}])
    plain = make_role({"http.GET": [EXAMPLE]})
    assign_in_order(user, [(conditional, "ctx1"), (plain, "ctx2")], reverse)
    in_ctx2 = ExampleAccessControlledModel.objects.create(name="a", rbac_context="ctx2")
    in_ctx3 = ExampleAccessControlledModel.objects.create(name="b", rbac_context="ctx3")
    client = client_for(user)

    assert client.get(EXAMPLE_URL.format(in_ctx2.pk)).status_code == 200
    # Filtered out of the queryset (RbacFilter): no role grants anything in ctx3.
    assert client.get(EXAMPLE_URL.format(in_ctx3.pk)).status_code == 404


@pytest.mark.django_db
def test_merging_roles_does_not_change_the_settings_default_policy(django_user_model):
    staff = django_user_model.objects.create(username="staff", is_staff=True)
    other_staff = django_user_model.objects.create(username="other", is_staff=True)
    default = policy_for_staff()
    default_json = default.to_json()
    role = make_role([{"http.GET": "status == 'ok'"}, {"http.PUT": "status == 'ok'"}])
    assign(staff, role, DEFAULT_CONTEXT)

    staff_policy = policy_for_user(staff)

    assert staff_policy.should_allow(get("Other"), DEFAULT_CONTEXT, OK)
    assert staff_policy.should_allow(
        get("rbac.ExampleAccessControlledModel"), DEFAULT_CONTEXT, NOT_OK
    )
    assert policy_for_staff() is default
    assert default.to_json() == default_json
    other_policy = policy_for_user(other_staff)
    assert not other_policy.should_allow(get("Other"), DEFAULT_CONTEXT, OK)
    assert not other_policy.should_allow(
        Permission("http.PUT", "Other"), DEFAULT_CONTEXT, OK
    )
    assert other_policy.should_allow(
        get("rbac.ExampleAccessControlledModel"), DEFAULT_CONTEXT, NOT_OK
    )


def overridden_defaults(monkeypatch, **defaults):
    """Replace `SCOPED_RBAC` settings `defaults` for a test. Resolved settings are
    cached in `conf.RESOLVED_SETTINGS`, so the cache is cleared for the test and the
    original restored afterwards."""
    original = conf.RESOLVED_SETTINGS
    with override_settings(SCOPED_RBAC={**settings.SCOPED_RBAC, **defaults}):
        monkeypatch.setattr(conf, "RESOLVED_SETTINGS", None)
        yield
    monkeypatch.undo()
    assert conf.RESOLVED_SETTINGS is original


@pytest.fixture
def context_condition_for_authenticated(monkeypatch):
    """The settings default policy for authenticated users is a context-level
    condition."""
    defaults = overridden_defaults(
        monkeypatch, POLICY_FOR_AUTHENTICATED={"condition": "false"}
    )
    for _ in defaults:
        assert policy_for_authenticated().to_json() == {
            "conditions": [{"condition": "false"}]
        }
        yield
    assert policy_for_authenticated().to_json() is False


@pytest.mark.django_db
def test_list_is_filtered_when_a_default_policy_has_a_context_condition(
    user, context_condition_for_authenticated
):
    grant(user, {"http.GET": [EXAMPLE, f"{EXAMPLE}/list"]}, "ctx2")
    ExampleAccessControlledModel.objects.create(name="a", rbac_context="ctx2")
    ExampleAccessControlledModel.objects.create(name="b", rbac_context="ctx3")

    response = client_for(user).get("/api/example-access-controlled-models/")

    assert response.status_code == 200, response.content
    # Only the ctx2 object; the ctx3 one is filtered out.
    assert response.data["count"] == 1


@pytest.mark.django_db
def test_a_role_assigned_in_two_contexts_grants_exactly_its_permissions(user):
    role = make_role([{"http.GET": "status == 'ok'"}, "http.PUT"])
    assign(user, role, "ctx1")
    assign(user, role, "ctx2")

    policy = policy_for_user(user)

    for rbac_context in ("ctx1", "ctx2", SOME_CONTEXT):
        assert policy.should_allow(get("Any"), rbac_context, OK), rbac_context
        assert not policy.should_allow(get("Any"), rbac_context, NOT_OK), rbac_context
        assert policy.should_allow(Permission("http.PUT", "Any"), rbac_context, NOT_OK)
        assert not policy.should_allow(Permission("http.DELETE", "Any"), rbac_context)
    assert not policy.should_allow(get("Any"), "ctx3", OK)
    assert not policy.should_allow(Permission("http.PUT", "Any"), "ctx3", OK)


# Defaults: a top-level condition merged with a context grant that is a condition (a
# `CompoundPolicy` at the root), and a top-level condition.
COMPOUND_DEFAULT_JSON = (
    {"condition": "status == 'ok'"},
    {"ctx1": {"http.GET": {"Thing": "kind == 'a'"}}},
)
CONDITION_DEFAULT_JSON = {"condition": "kind == 'staff'"}
DEFAULT_PROBES = [
    (Permission(action, resource_type), rbac_context, resource)
    for action in ("http.GET", "http.PUT")
    for resource_type in ("Thing", "Other")
    for rbac_context in ("ctx1", "ctx2", SOME_CONTEXT)
    for resource in (OK, NOT_OK, {"kind": "a"}, {"kind": "b"}, {"kind": "staff"}, {})
]


def allowed(policy, probes):
    """The `probes` a `Policy` allows."""
    return [
        probe
        for probe in probes
        if policy.should_allow(probe[1], *probe[0], resource=probe[2])
    ]


@pytest.fixture(params=["compound_for_authenticated", "compound_for_staff"])
def conditional_defaults(request, monkeypatch):
    """The compound default for authenticated users (so it is the root that the
    other default and roles are merged into) or for staff (so it is merged into a
    top-level condition)."""
    first, second = (policy_from_json(p) for p in COMPOUND_DEFAULT_JSON)
    defaults = [first.sum_with(second), CONDITION_DEFAULT_JSON]
    if request.param == "compound_for_staff":
        defaults.reverse()
    yield from overridden_defaults(
        monkeypatch, POLICY_FOR_AUTHENTICATED=defaults[0], POLICY_FOR_STAFF=defaults[1]
    )


@pytest.mark.django_db
def test_merging_roles_does_not_change_conditional_default_policies(
    django_user_model, conditional_defaults
):
    staff = django_user_model.objects.create(username="staff", is_staff=True)
    other_staff = django_user_model.objects.create(username="other", is_staff=True)
    defaults = [policy_for_authenticated(), policy_for_staff()]
    defaults_json = [p.to_json() for p in defaults]
    defaults_allow = [allowed(p, DEFAULT_PROBES) for p in defaults]
    assert all(defaults_allow)
    grant(
        staff,
        {"http.GET": {"Thing": {"condition": "kind == 'b'"}, "Other": True}},
        "ctx1",
    )
    grant(staff, {"http.PUT": ["Thing"]}, "ctx2")

    staff_policy = policy_for_user(staff)

    assert staff_policy.should_allow(get("Thing"), "ctx1", {"kind": "b"})
    assert staff_policy.should_allow(get("Other"), "ctx1", NOT_OK)
    assert staff_policy.should_allow(Permission("http.PUT", "Thing"), "ctx2", NOT_OK)
    assert staff_policy.should_allow(get("Thing"), "ctx1", {"kind": "a"})
    assert staff_policy.should_allow(get("Other"), "ctx2", {"kind": "staff"})
    assert not staff_policy.should_allow(get("Other"), "ctx2", NOT_OK)
    assert [policy_for_authenticated(), policy_for_staff()] == defaults
    assert [p.to_json() for p in defaults] == defaults_json
    assert [allowed(p, DEFAULT_PROBES) for p in defaults] == defaults_allow
    # policy_for also grants each default's context grants in SOME_CONTEXT.
    other_policy = policy_for_user(other_staff)
    assert [p for p in DEFAULT_PROBES if other_policy.should_allow(*p)] == [
        (permission, rbac_context, resource)
        for permission, rbac_context, resource in DEFAULT_PROBES
        if any(
            (permission, c, resource) in allow
            for allow in defaults_allow
            for c in (
                ("ctx1", "ctx2", SOME_CONTEXT)
                if rbac_context == SOME_CONTEXT
                else (rbac_context,)
            )
        )
    ]
