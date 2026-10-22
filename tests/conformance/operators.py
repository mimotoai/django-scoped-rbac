"""The operators that the conformance fixtures use. Their semantics are specified in
README.md, for other implementations to reproduce."""

from collections.abc import Mapping


def istrue(resource, configuration):
    """Allowed for the resource ``true`` and for an object whose "a" is 3."""
    return resource == True or (  # noqa: E712 (the test operator's original form)
        isinstance(resource, Mapping) and resource.get("a") == 3
    )


def a_at_least(resource, configuration):
    """Allowed if the resource's number "a" is at least ``configuration["min"]``,
    denied if it is less, and undetermined (``None``) if the resource is not an
    object or its "a" is missing or not a number."""
    if not isinstance(resource, Mapping):
        return None
    a = resource.get("a")
    if isinstance(a, bool) or not isinstance(a, int | float):
        return None
    return a >= configuration["min"]


OPERATORS = {"istrue": istrue, "a_at_least": a_at_least}
