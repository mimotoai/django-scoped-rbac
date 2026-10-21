import pytest
from cel_expr_python import cel
from django.core.exceptions import ImproperlyConfigured

from scoped_rbac.cel import (
    InvalidExpression,
    compile_expression,
    function_decl,
    is_true,
    new_environment,
)
from scoped_rbac.policy import Permission, policy_from_json


def starts_with_draft(status: str) -> bool:
    return status.startswith("draft")


def has_key(mapping: dict, key: str) -> bool:
    return key in mapping


def unannotated(value):
    return True


def explodes(value: str) -> bool:
    raise ValueError("boom")


def evaluate(expression, data, **functions):
    return is_true(compile_expression(expression, new_environment(functions)), data)


def test_annotated_functions_are_callable_from_expressions():
    assert evaluate(
        "is_draft(status)", {"status": "draft-1"}, is_draft=starts_with_draft
    )
    assert not evaluate(
        "is_draft(status)", {"status": "final"}, is_draft=starts_with_draft
    )
    assert evaluate("has_key(content, 'a')", {"content": {"a": 1}}, has_key=has_key)


def test_any_annotation_is_rejected():
    def anything(value: object) -> bool:
        return True

    with pytest.raises(ImproperlyConfigured):
        function_decl("anything", anything)


def test_function_given_by_qualified_name():
    assert evaluate(
        "is_draft(status)",
        {"status": "draft"},
        is_draft="tests.test_cel.starts_with_draft",
    )


def test_function_decl_is_used_as_is():
    decl = cel.FunctionDecl(
        "twice",
        [cel.Overload("twice_int", cel.Type.INT, [cel.Type.INT], impl=lambda x: 2 * x)],
    )
    assert function_decl("ignored", decl) is decl
    assert evaluate("twice(n) == 4", {"n": 2}, twice=decl)


def test_unannotated_function_is_rejected():
    with pytest.raises(ImproperlyConfigured, match="'value' must be annotated"):
        function_decl("unannotated", unannotated)


@pytest.mark.parametrize(
    "expression, data",
    [
        ("missing.field == 1", {}),
        ("explodes(status)", {"status": "x"}),
        ("1 + 1", {}),
    ],
)
def test_errors_and_non_boolean_results_fail_closed(expression, data):
    assert evaluate(expression, data, explodes=explodes) is False


def test_syntax_error_raises_invalid_expression():
    with pytest.raises(InvalidExpression, match="content."):
        compile_expression("content.", new_environment({}))


def test_non_mapping_data_is_rejected():
    with pytest.raises(TypeError, match="must be a mapping"):
        evaluate("true", ["not", "a", "mapping"])


def test_policy_condition_evaluates_against_resource():
    policy = policy_from_json(
        {"GET": {"Thing": {"condition": "content.status == 'ok'"}}}
    )
    assert policy.should_allow(
        *Permission("GET", "Thing"), resource={"content": {"status": "ok"}}
    )
    assert not policy.should_allow(
        *Permission("GET", "Thing"), resource={"content": {}}
    )
