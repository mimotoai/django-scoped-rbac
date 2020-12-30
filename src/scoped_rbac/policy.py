"""
RBAC Policies, with stubbed-out support for conditional expressions.
"""

from collections import namedtuple
import json


Permission = namedtuple("Permission", "action, resource_type")


class Policy:
    def should_allow(self, *args, **kwargs):
        raise NotImplementedError()

    def sum_with(self, other_policy):
        raise NotImplementedError()

    def __repr__(self):
        raise NotImplementedError()

    def to_json(self):
        raise NotImplementedError()


class PolicyBoolean(Policy):
    ...


class PolicyTrue(PolicyBoolean):
    def should_allow(self, *args, **kwargs):
        return True

    def sum_with(self, other_policy):
        return self

    def __repr__(self):
        return "PolicyTrue"

    def to_json(self):
        return True


class PolicyFalse(PolicyBoolean):
    def should_allow(self, *args, **kwargs):
        return False

    def sum_with(self, other_policy):
        return other_policy

    def __repr__(self):
        return "PolicyFalse"

    def to_json(self):
        return False


POLICY_TRUE = PolicyTrue()
POLICY_FALSE = PolicyFalse()


class Expression(Policy):
    """
    Expression policies are initialized with a `dict` detailing the parameters
    to use in evaluating the expression to determine whether the policy
    conditions are met.
    """

    def __init__(self, expression):
        self.expression = expression

    def evaluate(self, permission, context_id, resource=None):
        raise NotImplementedError()

    def should_allow(self, permission, context_id, resource=None):
        return self.evaluate(self, permission, context_id, resource)

    def sum_with(self, other_policy):
        if isinstance(other_policy, PolicyBoolean):
            return other_policy.sum_with(self)
        if isinstance(other_policy, Expression):
            return ExpressionList(self, other_policy)
        if isinstance(other_policy, PolicySet):
            return CompoundPolicy(expression=self, policy_set=other_policy)
        if isinstance(other_policy, PolicyDict):
            return CompoundPolicy(expression=self, policy_dict=other_policy)
        if isinstance(other_policy, CompoundPolicy):
            return other_policy.add_expression(self)

    def __repr__(self):
        return f"Expression {repr(self.expression)}"

    def to_json(self):
        return self.expression

    @classmethod
    def from_json(cls, json_policy):
        return Expression(json_policy)


class ExpressionList(Policy):
    def __init__(self, *args):
        self.expressions = args

    def should_allow(self, *args, **kwargs):
        for expression in self.expressions:
            if expression.should_allow(*args, **kwargs):
                return True
        return False

    def sum_with(self, other_policy):
        if isinstance(other_policy, PolicyBoolean):
            return other_policy.sum_with(self)
        if isinstance(other_policy, Expression):
            return self.add(other_policy)
        if isinstance(other_policy, PolicySet):
            return CompoundPolicy(expression=self, policy_set=other_policy)
        if isinstance(other_policy, PolicyDict):
            return CompoundPolicy(expression=self, policy_dict=other_policy)
        if isinstance(other_policy, CompoundExpression):
            return other_policy.add_expression(self)

    def add(self, expression):
        return ExpressionList(expression, *self.expressions)

    def __repr__(self):
        return f"ExpressionList [ {', '.join([repr(expr) for expr in self.expressions])}  ]"

    def to_json(self):
        return [expr.to_json() for expr in self.expressions]

    @classmethod
    def from_json(cls, json_policy):
        return ExpressionList(*[Expression.from_json(item) for item in json_policy])


class PolicySet(Policy):
    def __init__(self, *args):
        self.allowed = set(args)

    def should_allow(self, *args, **kwargs):
        if len(args) is 0:
            return False
        key = args[0]
        return key in self.allowed

    def sum_with(self, other_policy):
        if (
            isinstance(other_policy, PolicyBoolean)
            or isinstance(other_policy, Expression)
            or isinstance(other_policy, ExpressionList)
        ):
            return other_policy.sum_with(self)
        if isinstance(other_policy, PolicySet):
            return PolicySet(*self.allowed.union(other_policy.allowed))
        if isinstance(other_policy, PolicyDict):
            return other_policy.add_all([(key, POLICY_TRUE) for key in self.allowed])
        if isinstance(other_policy, CompoundPolicy):
            return other_policy.add_policy_set(self)
        raise NotImplementedError(f"Unsupported type {type(other_policy)}")

    def __repr__(self):
        return f"PolicySet {repr(self.allowed)}"

    def to_json(self):
        """Convert to JSON. Returns a sorted list so that the representation of the set
        may be stable for testing and other purposes.
        """
        return sorted(list(self.allowed))

    @classmethod
    def from_json(cls, json_policy):
        if isinstance(json_policy, str):
            return PolicySet(json_policy)
        return PolicySet(*json_policy)


class PolicyDict(Policy):
    def __init__(self, policy_dict):
        self.policies = policy_dict

    def should_allow(self, *args, **kwargs):
        if len(args) is 0:
            return False
        key = args[0]
        policy = self.policies.get(key, POLICY_FALSE)
        return policy.should_allow(*args[1:], *kwargs)

    def sum_with(self, other_policy):
        if (
            isinstance(other_policy, PolicyBoolean)
            or isinstance(other_policy, Expression)
            or isinstance(other_policy, ExpressionList)
        ):
            return other_policy.sum_with(self)
        if isinstance(other_policy, PolicySet):
            return other_policy.sum_with(self)
        if isinstance(other_policy, PolicyDict):
            return self.recursive_sum_with(other_policy)
        if isinstance(other_policy, CompoundPolicy):
            return other_policy.add_policy_set(self)
        raise NotImplementedError(f"Unsupported type {type(other_policy)}")

    def add_all(self, key_policy_pairs):
        policies = dict(self.policies)
        for key, policy in key_policy_pairs:
            current = policies.get(key, POLICY_FALSE)
            policies[key] = policy.sum_with(current)
        return PolicyDict(policies)

    def recursive_sum_with(self, other_policy):
        policies = dict(self.policies)
        for k, v in other_policy.policies.items():
            current_policy = policies.get(k, POLICY_FALSE)
            policies[k] = current_policy.sum_with(v)
        return PolicyDict(policies)

    def __repr__(self):
        return f"PolicyDict {repr(self.policies)}"

    def to_json(self):
        return {k: v.to_json() for k, v in self.policies.items()}

    @classmethod
    def from_json(cls, json_policy):
        policies = {key: policy_from_json(value) for key, value in json_policy.items()}
        return PolicyDict(policies)

    def keys(self):
        return self.policies.keys()


class CompoundPolicy(Policy):
    def __init__(self, policy_dict=None, policy_set=None, expressions=None):
        self.policy_dict = policy_dict or PolicyDict({})
        if policy_set:
            self.policy_dict = self.policy_dict.sum_with(policy_set)
        self.expressions = expressions or ExpressionList()

    def should_allow(self, *args, **kwargs):
        return self.policy_dict.should_allow(
            *args, **kwargs
        ) or self.expressions.should_allow(*args, **kwargs)

    def sum_with(self, other_policy):
        return other_policy.sum_with(self)

    def add_expression(self, expression):
        return CompoundPolicy(
            policy_dict=self.policy_dict,
            expressions=self.expressions.sum_with(expression),
        )

    def add_policy_set(self, policy_set):
        return CompoundPolicy(
            policy_dict=self.policy_dict,
            policy_set=policy_set,
            expressions=self.expressions,
        )

    def add_policy_dict(self, policy_dict):
        return CompoundPolicy(
            policy_dict=self.policy_dict.sum_with(policy_dict),
            expressions=self.expressions,
        )

    def __repr__(self):
        return (
            f"CompoundPolicy {{ expressions: {repr(self.expressions)}, "
            f"policy_dict: {repr(self.policy_dict)} }}"
        )

    def to_json(self):
        ret = dict()
        if self.expressions is not None:
            ret["expressions"] = expressions.to_json()
        if self.policy_dict is not None and self.policy_dict.keys():
            ret["policy_dict"] = policy_dict.to_json()
        return ret

    @classmethod
    def from_json(cls, json_policy):
        expressions = None
        policy_dict = None
        if "expressions" in json_policy:
            expressions = ExpressionList.from_json(json_policy["expressions"])
        if "policy_dict" in json:
            policy_dict = PolicyDict.from_json(json_policy["policy_dict"])
        return CompoundPolicy(policy_dict=policy_dict, expressions=expressions)


def policy_from_json(json_policy):
    if json_policy is True:
        return POLICY_TRUE
    if json_policy is False:
        return POLICY_FALSE
    if isinstance(json_policy, list) or isinstance(json_policy, str):
        return PolicySet.from_json(json_policy)
    if isinstance(json_policy, dict):
        if "expressions" in json_policy or "policy_dict" in json_policy:
            return CompoundPolicy.from_json(json_policy)
        return PolicyDict.from_json(json_policy)


class RootPolicy:
    def __init__(self):
        self.policy = POLICY_FALSE

    def should_allow(self, permission, context_id, resource=None):
        return self.policy.should_allow(context_id, *permission, resource=resource)

    def add_json_policy_for_context(self, json_policy, context):
        policy = policy_from_json(json_policy)
        self.add_policy(PolicyDict({context: policy}))
        return self

    def add_policy_for_context(self, policy, context):
        self.add_policy(PolicyDict({context: policy}))
        return self

    def add_policy(self, policy):
        self.policy = self.policy.sum_with(policy)
        return self

    def __repr__(self):
        return f"RootPolicy {repr(self.policy)}"

    def to_json(self):
        return self.policy.to_json()

    def get_contexts_for(self, permission):
        # FIXME This isn't done, yet
        if isinstance(self.policy, PolicyDict):
            return self.policy.keys()
        if isinstance(self.policy, CompoundPolicy) and self.policy.expressions is None:
            return self.policy.policy_dict.keys()
        return None
