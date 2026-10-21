"""
Common Expression Language (CEL) support for policy conditions, backed by Google's
`cel-expr-python <https://github.com/cel-expr/cel-python>`_ runtime.

Expressions are compiled without type checking so that, as with JSON policies, the
shape of a resource does not need to be declared up front. Each top-level key of the
resource mapping is available as a variable in the expression.

The CEL runtime dispatches functions on the concrete types of their arguments, so
functions registered via ``SCOPED_RBAC["CEL_FUNCTIONS"]`` must either be a
``cel.FunctionDecl`` or a callable whose parameters are annotated with Python types
that map onto CEL types. A function accepting several argument types needs a
``cel.FunctionDecl`` with an overload for each. For example:

.. code-block:: python

   def is_allowed_transition(current: str, proposed: str) -> bool:
       ...

   SCOPED_RBAC = {
       "CEL_FUNCTIONS": {
           "is_allowed_transition": "myapp.workflow.is_allowed_transition",
       }
   }
"""

import inspect
import logging
import typing
from collections.abc import Mapping

from cel_expr_python import cel
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

logger = logging.getLogger(__name__)


class InvalidExpression(ValueError):
    """A CEL expression that cannot be compiled, such as one with a syntax error."""


PYTHON_TO_CEL_TYPES = {
    bool: cel.Type.BOOL,
    int: cel.Type.INT,
    float: cel.Type.DOUBLE,
    str: cel.Type.STRING,
    bytes: cel.Type.BYTES,
    dict: cel.Type.Map(cel.Type.DYN, cel.Type.DYN),
    list: cel.Type.List(cel.Type.DYN),
}


def cel_type_for(annotation):
    """The CEL type for a Python type annotation, or ``None`` if it has no mapping."""
    return PYTHON_TO_CEL_TYPES.get(typing.get_origin(annotation) or annotation)


def function_decl(name, func):
    """Build a ``cel.FunctionDecl`` named `name` from a type-annotated callable. A
    ``cel.FunctionDecl`` or the fully qualified name of either is also accepted.
    """
    if isinstance(func, str):
        func = import_string(func)
    if isinstance(func, cel.FunctionDecl):
        return func

    hints = typing.get_type_hints(func)
    parameter_types = []
    for parameter in inspect.signature(func).parameters.values():
        parameter_type = cel_type_for(hints.get(parameter.name))
        if parameter_type is None:
            raise ImproperlyConfigured(
                f"CEL function {name!r} parameter {parameter.name!r} must be "
                f"annotated with one of {[t.__name__ for t in PYTHON_TO_CEL_TYPES]}, "
                f"or the function declared with cel.FunctionDecl."
            )
        parameter_types.append(parameter_type)
    return_type = cel_type_for(hints.get("return")) or cel.Type.DYN

    overload_id = "_".join([name, *(t.name() for t in parameter_types)])
    return cel.FunctionDecl(
        name, [cel.Overload(overload_id, return_type, parameter_types, impl=func)]
    )


def new_environment(functions):
    """A CEL environment with the `functions` mapping of name to function registered."""
    return cel.NewEnv(
        functions=[function_decl(name, func) for name, func in functions.items()]
    )


def compile_expression(expression, environment=None):
    """Compile `expression` in `environment`, which defaults to the environment
    configured by ``SCOPED_RBAC`` settings. Raises :class:`InvalidExpression` if the
    expression cannot be compiled.
    """
    if environment is None:
        from .conf import cel_environment

        environment = cel_environment()
    try:
        return environment.compile(expression, disable_check=True)
    except RuntimeError as e:
        raise InvalidExpression(f"Invalid CEL expression {expression!r}: {e}") from e


def is_true(compiled_expression, data):
    """Evaluate `compiled_expression` against the `data` mapping. Only a boolean
    ``true`` result counts as true, so evaluation errors such as a missing field or
    an exception in a registered function fail closed.
    """
    if data is not None and not isinstance(data, Mapping):
        raise TypeError(f"CEL data must be a mapping, not {type(data).__name__}")
    result = compiled_expression.eval(data=data)
    if result.type() == cel.Type.ERROR:
        logger.debug("CEL evaluation error: %s", result.value())
    return result.type() == cel.Type.BOOL and result.value() is True
