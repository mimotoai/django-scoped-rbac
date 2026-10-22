"""
RBAC policies.

A policy is a tree of :class:`PolicyNode` objects. Each node may allow everything
below it (``allow_all``), has named ``children`` that are followed by the keys of a
request (context, then action IRI, then resource type IRI), and has ``conditions``
(:class:`Expression` or :class:`Operator`) that are evaluated against the resource.
Policies are immutable; merging two (:meth:`Policy.sum_with`) is a logical OR that
returns a new policy.
"""

import enum
import json
import logging
import warnings
from collections import namedtuple
from types import MappingProxyType

from .cel import compile_expression
from .cel import evaluate as evaluate_cel
from .conf import operators

logger = logging.getLogger(__name__)


Permission = namedtuple("Permission", "action, resource_type")


class Decision(enum.Enum):
    """The outcome of evaluating a policy. ``UNDETERMINED`` means that a condition
    could not be decided, e.g. because the resource lacks a value it refers to.
    Only ``ALLOWED`` allows a request.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    UNDETERMINED = "undetermined"


def _decision(value):
    """The :class:`Decision` for ``True``, ``False`` or ``None`` (undetermined)."""
    if value is None:
        return Decision.UNDETERMINED
    return Decision.ALLOWED if value else Decision.DENIED


class Policy:
    """Base class of policies: :class:`PolicyNode` and the conditions
    :class:`Expression` and :class:`Operator`."""

    def evaluate(self, *keys, resource=None):
        """The :class:`Decision` for a request named by `keys` (context, action IRI,
        resource type IRI) on `resource`."""
        raise NotImplementedError()

    def should_allow(self, *keys, resource=None):
        """``True`` if, and only if, :meth:`evaluate` is ``ALLOWED``."""
        return self.evaluate(*keys, resource=resource) is Decision.ALLOWED

    def sum_with(self, other_policy):
        """A new policy allowing what either this or `other_policy` allows."""
        return as_node(self).sum_with(other_policy)

    def __repr__(self):
        raise NotImplementedError()

    def to_json(self):
        raise NotImplementedError()


class Condition(Policy):
    """A condition on the resource: an :class:`Expression` or an :class:`Operator`,
    with an optional `message` describing it (e.g. for a client to show when it
    is not met). As a policy it applies whatever the keys of the request.
    """

    message = None

    def evaluate(self, *keys, resource=None):
        return self.evaluate_condition(resource)

    def evaluate_condition(self, resource):
        raise NotImplementedError()

    def condition_json(self):
        """The value of the ``"condition"`` key of :meth:`to_json`."""
        raise NotImplementedError()

    def to_json(self):
        """The condition as in policy JSON: ``{"condition": ...}``, with its
        ``"message"`` if it has one."""
        json_condition = {"condition": self.condition_json()}
        if self.message is not None:
            json_condition["message"] = self.message
        return json_condition

    def _identity(self):
        raise NotImplementedError()

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return self._identity() == other._identity()

    def __hash__(self):
        value = self._identity()[0]
        return hash((type(self).__name__, value if isinstance(value, str) else None))


def _condition_parts(json_condition, value_type):
    """`json_condition` as (value, message): either a bare value of `value_type` or
    a condition dict ``{"condition": value, "message": ...}``."""
    if isinstance(json_condition, dict) and "condition" in json_condition:
        return json_condition["condition"], json_condition.get("message")
    if isinstance(json_condition, value_type):
        return json_condition, None
    raise ValueError(f"Invalid condition {json_condition!r}")


class Expression(Condition):
    """A CEL expression condition (see :mod:`scoped_rbac.cel`). It is allowed when
    the expression is ``true`` for the resource, denied when ``false``, and
    undetermined when it cannot be evaluated (such as a missing value) or is not a
    boolean.
    """

    def __init__(self, expression, message=None):
        self.expression = expression
        self.message = message
        self.compiled_expression_ = None

    @property
    def compiled_expression(self):
        if self.compiled_expression_ is None:
            self.compiled_expression_ = compile_expression(self.expression)
        return self.compiled_expression_

    def evaluate_condition(self, resource):
        """Expects `resource` to be a mapping, ``None``, or have a ``to_cel()``
        method returning a mapping."""
        if hasattr(resource, "to_cel"):
            resource = resource.to_cel()
        return _decision(evaluate_cel(self.compiled_expression, resource))

    def condition_json(self):
        return self.expression

    def _identity(self):
        return (self.expression, self.message)

    def __repr__(self):
        if self.message is None:
            return f"Expression {self.expression!r}"
        return f"Expression {self.expression!r} message={self.message!r}"

    @classmethod
    def from_json(cls, json_policy):
        """An Expression from a CEL string or a condition dict."""
        return cls(*_condition_parts(json_policy, str))


class Operator(Condition):
    """A condition evaluated by a registered operator function (see
    :func:`scoped_rbac.conf.operators`), configured by a dict whose ``"operator"``
    key names it. The function is called as ``function(resource, configuration)``:
    a result of ``None`` is undetermined, otherwise a truthy result allows and a
    falsy one denies.
    """

    def __init__(self, configuration, message=None):
        self.configuration = configuration
        self.message = message
        self.operator_name = configuration.get("operator", None)
        self.operator = None

    @property
    def resolved_operator(self):
        return operators().get(self.operator_name)

    def evaluate_condition(self, resource):
        return _decision(self.resolved_operator(resource, self.configuration))

    def condition_json(self):
        return self.configuration

    def _identity(self):
        return (self.operator_name, self.configuration, self.message)

    def __repr__(self):
        if self.message is None:
            return json.dumps(self.configuration)
        return f"{json.dumps(self.configuration)} message={self.message!r}"

    @classmethod
    def from_json(cls, json_policy):
        """An Operator from its configuration dict or a condition dict."""
        return cls(*_condition_parts(json_policy, dict))


def _without_duplicates(conditions):
    unique = []
    for condition in conditions:
        if not isinstance(condition, Condition):
            raise TypeError(f"Not a condition: {condition!r}")
        if condition not in unique:
            unique.append(condition)
    return tuple(unique)


class PolicyNode(Policy):
    """The policy node. Immutable.

    - `allow_all`: allow every request that reaches this node. Such a node has no
      children or conditions (they would allow nothing more).
    - `children`: a read-only mapping of key to the node for requests whose next
      key it is.
    - `conditions`: a tuple of distinct conditions, any one of which allows.

    Evaluating a node for `keys` and a resource (Kleene OR, in this order, stopping
    at the first ``ALLOWED``): ``ALLOWED`` if `allow_all`; then the child for
    ``keys[0]`` evaluated for the remaining keys; then each condition. Otherwise
    ``UNDETERMINED`` if any of those was, else ``DENIED``.
    """

    __slots__ = ("allow_all", "children", "conditions")

    def __init__(self, allow_all=False, children=None, conditions=()):
        allow_all = bool(allow_all)
        if allow_all:
            children, conditions = {}, ()
        children = {key: as_node(child) for key, child in (children or {}).items()}
        object.__setattr__(self, "allow_all", allow_all)
        object.__setattr__(self, "children", MappingProxyType(children))
        object.__setattr__(self, "conditions", _without_duplicates(conditions))

    def __setattr__(self, name, value):
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name):
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other):
        if not isinstance(other, PolicyNode):
            return NotImplemented
        return (
            self.allow_all == other.allow_all
            and dict(self.children) == dict(other.children)
            and self.conditions == other.conditions
        )

    def __hash__(self):
        return hash((self.allow_all, frozenset(self.children.items()), self.conditions))

    @property
    def is_empty(self):
        """True if this node has nothing: it allows nothing and evaluates
        nothing."""
        return not (self.allow_all or self.children or self.conditions)

    def evaluate(self, *keys, resource=None):
        return self._evaluate(keys, resource)

    def _children_for(self, key):
        child = self.children.get(key)
        return () if child is None else (child,)

    def _evaluate(self, keys, resource):
        if self.allow_all:
            return Decision.ALLOWED
        undetermined = False
        if keys:
            for child in self._children_for(keys[0]):
                decision = child._evaluate(keys[1:], resource)
                if decision is Decision.ALLOWED:
                    return decision
                undetermined = undetermined or decision is Decision.UNDETERMINED
        for condition in self.conditions:
            decision = condition.evaluate_condition(resource)
            if decision is Decision.ALLOWED:
                return decision
            undetermined = undetermined or decision is Decision.UNDETERMINED
        return Decision.UNDETERMINED if undetermined else Decision.DENIED

    def sum_with(self, other_policy):
        other = as_node(other_policy)
        if self.allow_all or other.is_empty:
            return self
        if other.allow_all or self.is_empty:
            return other
        children = dict(self.children)
        for key, child in other.children.items():
            children[key] = children[key].sum_with(child) if key in children else child
        return PolicyNode(False, children, self.conditions + other.conditions)

    def __repr__(self):
        return f"PolicyNode {self.to_json()!r}"

    def to_json(self):
        """The node as JSON: ``true`` if it allows all, ``false`` if it is empty,
        otherwise an object with ``"children"`` (keys sorted) and ``"conditions"``,
        each present only if non-empty."""
        if self.allow_all:
            return True
        if self.is_empty:
            return False
        node_json = {}
        if self.children:
            node_json["children"] = {
                key: self.children[key].to_json() for key in sorted(self.children)
            }
        if self.conditions:
            node_json["conditions"] = [c.to_json() for c in self.conditions]
        return node_json

    @classmethod
    def from_json(cls, node_json):
        """The node for :meth:`to_json`'s output."""
        if node_json is True:
            return POLICY_TRUE
        if node_json is False:
            return POLICY_FALSE
        children = {
            key: cls.from_json(child)
            for key, child in node_json.get("children", {}).items()
        }
        conditions = [condition_from_json(c) for c in node_json.get("conditions", [])]
        return cls(False, children, conditions)


POLICY_TRUE = PolicyNode(allow_all=True)
POLICY_FALSE = PolicyNode()


def as_node(policy):
    """`policy` as a :class:`PolicyNode`: a condition becomes a node with that one
    condition. Raises ``NotImplementedError`` for anything else."""
    if isinstance(policy, PolicyNode):
        return policy
    if isinstance(policy, Condition):
        return PolicyNode(conditions=(policy,))
    raise NotImplementedError(f"Unsupported type {type(policy)}")


def condition_from_json(json_condition):
    """The condition for a condition dict ``{"condition": <CEL string or operator
    configuration>, "message": ...}`` (the message is optional)."""
    value = json_condition["condition"]
    message = json_condition.get("message")
    if isinstance(value, dict) and "operator" in value:
        return Operator(value, message)
    return Expression(value, message)


# Deprecated constructors of the node classes before 0.10. Each returns the
# equivalent PolicyNode.


def _warn_deprecated(name):
    warnings.warn(
        f"{name} is deprecated and returns a PolicyNode; build policies with "
        "policy_from_json or PolicyNode.",
        DeprecationWarning,
        stacklevel=3,
    )


def _merged(policies):
    total = POLICY_FALSE
    for p in policies:
        total = total.sum_with(p)
    return total


def PolicyTrue():
    """Deprecated: use :data:`POLICY_TRUE`."""
    _warn_deprecated("PolicyTrue")
    return POLICY_TRUE


def PolicyFalse():
    """Deprecated: use :data:`POLICY_FALSE`."""
    _warn_deprecated("PolicyFalse")
    return POLICY_FALSE


def PolicySet(*args):
    """Deprecated: a :class:`PolicyNode` allowing everything under each key."""
    _warn_deprecated("PolicySet")
    return _set(*args)


def PolicyDict(policy_dict):
    """Deprecated: a :class:`PolicyNode` with `policy_dict` as its children."""
    _warn_deprecated("PolicyDict")
    return PolicyNode(children=policy_dict)


def ExpressionList(*args):
    """Deprecated: a :class:`PolicyNode` merging the given policies (usually
    conditions)."""
    _warn_deprecated("ExpressionList")
    return _merged(args)


def CompoundPolicy(policy_dict=None, policy_set=None, expressions=None):
    """Deprecated: a :class:`PolicyNode` merging the given policies."""
    _warn_deprecated("CompoundPolicy")
    return _merged(p for p in (policy_dict, policy_set, expressions) if p is not None)


def _set(*keys):
    return PolicyNode(children={key: POLICY_TRUE for key in keys})


def _dict(policy_dict):
    return PolicyNode(children=policy_dict)


def policy_from_json(json_policy):
    """Build a complete policy for a RBAC context"""
    if isinstance(json_policy, bool):
        return policy_from_bool(json_policy)
    elif isinstance(json_policy, str):
        return _set(json_policy)
    elif isinstance(json_policy, list):
        return policy_from_action_policy_list(json_policy)
    elif isinstance(json_policy, dict) and "condition" in json_policy:
        return as_node(policy_from_condition(json_policy))
    elif isinstance(json_policy, dict):
        return _dict(
            {key: action_policy_from_json(value) for key, value in json_policy.items()}
        )
    else:
        raise Exception(f"Invalid policy content {json_policy}")


def action_policy_from_json(json_policy):
    """The structure of an RBAC action policy in something like BNF:
    ```
    ActionPolicy: Bool | Condition | String::ActionName | ActionPolicyList | ActionPolicyDict
    ActionPolicyList: [ (String::ActionName | ActionCondition)+ ]
    ActionPolicyDict: { (String::ActionName: (Bool | Condition | String::ResourceName | ResourcePolicyList | ResourcePolicyDict))+ }
    ActionCondition: { String::ActionName: String::Expr | Condition }
    ResourcePolicyList: [ (String::ResourceName | ResourceCondition)+ ]
    ResourcePolicyDict: { (String::ResourceName: (Bool | String::Expr))+ }
    ResourceCondition: { String::ResourceName: String::Expr | OperatorConfig }
    Condition: { 'condition': String::Expr | OperatorConfig, ['message': String] }
    OperatorConfig: { 'operator': String::OperatorName, additionalProperties... }
    ```
    """
    if isinstance(json_policy, bool):
        return policy_from_bool(json_policy)
    elif isinstance(json_policy, str):
        return _set(json_policy)
    elif isinstance(json_policy, list):
        return policy_from_action_policy_list(json_policy)
    elif isinstance(json_policy, dict):
        return policy_from_action_policy_dict(json_policy)
    else:
        raise Exception(f"Invalid policy content {json_policy}")


def policy_from_action_policy_list(policy_list):
    """
    ```
    ActionPolicyList: [ (String::ActionName | ActionCondition)+ ]
    ```
    """

    def as_policy(x):
        if isinstance(x, str):
            return _set(x)
        else:
            return policy_from_action_condition(x)

    total = POLICY_FALSE
    for p in policy_list:
        total = total.sum_with(as_policy(p))
    return total


def policy_from_action_policy_dict(policy_dict):
    """
    ```
    ActionPolicyDict: { (String::ActionName: (Bool | Condition | String::ResourceName | ResourcePolicyList | ResourcePolicyDict))+ }
    ```
    """

    def as_policy(x):
        if isinstance(x, bool):
            return policy_from_bool(x)
        elif isinstance(x, str):
            return _set(x)
        elif isinstance(x, dict) and "condition" in x:
            return policy_from_condition(x)
        elif isinstance(x, list):
            return policy_from_resource_policy_list(x)
        elif isinstance(x, dict):
            return policy_from_resource_policy_dict(x)
        else:
            raise Exception(f"Invalid action policy dictionary value {x}")

    return _dict({key: as_policy(value) for key, value in policy_dict.items()})


def policy_from_action_condition(action_condition):
    """
    ```
    ActionCondition: { String::ActionName: String::Expr | Condition }
    ```
    """

    def as_condition(value):
        if isinstance(value, dict) and "condition" in value:
            return policy_from_condition(value)
        return Expression(value)

    return _dict({key: as_condition(value) for key, value in action_condition.items()})


def policy_from_resource_policy_list(policy_list):
    """
    ```
    ResourcePolicyList: [ (String::ResourceName | ResourceCondition)+ ]
    ```
    """

    def as_policy(x):
        if isinstance(x, str):
            return _set(x)
        else:
            return policy_from_resource_condition(x)

    total = POLICY_FALSE
    for p in policy_list:
        total = total.sum_with(as_policy(p))
    return total


def policy_from_resource_policy_dict(policy_dict):
    """
    ```
    ResourcePolicyDict: { (String::ResourceName: (Bool | String::Expr))+ }
    ```
    """

    def as_policy(x):
        if isinstance(x, bool):
            return policy_from_bool(x)
        else:
            return Expression(x)

    return _dict({key: as_policy(value) for key, value in policy_dict.items()})


def policy_from_resource_condition(resource_condition):
    """
    ```
    ResourceCondition: { String::ResourceName: String::Expr | OperatorConfig }
    ```
    """
    if isinstance(resource_condition, str):
        return _dict(
            {key: Expression(value) for key, value in resource_condition.items()}
        )
    elif isinstance(resource_condition, dict) and "operator" in resource_condition:
        return Operator(resource_condition)


def policy_from_condition(condition):
    """
    ```
    Condition: { 'condition': String::Expr | OperatorConfig, ['message': String] }
    ```
    A value that is neither (which the grammar does not allow, issue #17) is kept
    as an Expression, which fails when it is evaluated.
    """
    condition_value = condition.get("condition")
    message = condition.get("message")
    if isinstance(condition_value, dict) and "operator" in condition_value:
        return Operator(condition_value, message)
    return Expression(condition_value, message)


def policy_from_bool(b):
    if b:
        return POLICY_TRUE
    else:
        return POLICY_FALSE


class RootPolicy:
    """A user's effective policy: :attr:`policy` is a node whose keys are contexts,
    then action IRIs, then resource type IRIs."""

    def __init__(self):
        self.policy = POLICY_FALSE

    def evaluate(self, permission, context_id, resource=None):
        """The :class:`Decision` for `permission` in `context_id` on `resource`."""
        return self.policy.evaluate(context_id, *permission, resource=resource)

    def should_allow(self, permission, context_id, resource=None):
        """``True`` if, and only if, :meth:`evaluate` is ``ALLOWED``."""
        return self.evaluate(permission, context_id, resource) is Decision.ALLOWED

    def add_json_policy_for_context(self, json_policy, context):
        return self.add_policy_for_context(policy_from_json(json_policy), context)

    def add_policy_for_context(self, policy, context):
        self.add_policy(PolicyNode(children={context: policy}))
        return self

    def add_policy(self, policy):
        self.policy = self.policy.sum_with(policy)
        return self

    def __repr__(self):
        return f"RootPolicy {repr(self.policy)}"

    def to_json(self):
        return self.policy.to_json()

    def get_contexts_for(self, permission):
        """The contexts a GET list is restricted to, or ``None`` for no
        restriction. Top-level conditions are ignored, so filtering fails closed
        when there are also context grants (issue #5)."""
        # FIXME This ignores `permission` (issue #5).
        if self.policy.allow_all or not self.policy.children:
            return None
        return list(self.policy.children)
