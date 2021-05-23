"""
RBAC Policies, with stubbed-out support for conditional expressions.
"""

from celpy.celtypes import BoolType
from collections import namedtuple
from .conf import cel_functions, operators
import celpy
import json
import logging


logger = logging.getLogger(__name__)


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
        self.compiled_expression_ = None

    @property
    def compiled_expression(self):
        if self.compiled_expression_ is None:
            env = celpy.Environment()
            ast = env.compile(self.expression)
            self.compiled_expression_ = env.program(ast, functions=cel_functions())
        return self.compiled_expression_

    def should_allow(self, *args, resource=None, **kwargs):
        """Expects `resource` to support dictionary access or have a `to_cel()` method"""
        if hasattr(resource, "to_cel"):
            return self.compiled_expression.evaluate(resource.to_cel()) == BoolType(
                True
            )
        else:
            return self.compiled_expression.evaluate(resource) == BoolType(True)

    def sum_with(self, other_policy):
        if isinstance(other_policy, PolicyBoolean):
            return other_policy.sum_with(self)
        if isinstance(other_policy, Expression) or isinstance(other_policy, Operator):
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


class Operator(Policy):
    """
    Expression policies are initialized with a `dict` detailing the parameters
    to use in evaluating the expression to determine whether the policy
    conditions are met.
    """

    def __init__(self, configuration):
        self.configuration = configuration
        self.operator_name = configuration.get("operator", None)
        self.operator = None

    @property
    def resolved_operator(self):
        return operators().get(self.operator_name)

    def should_allow(self, *args, resource=None, **kwargs):
        return self.resolved_operator(resource, self.configuration)

    def sum_with(self, other_policy):
        if isinstance(other_policy, PolicyBoolean):
            return other_policy.sum_with(self)
        if isinstance(other_policy, Expression) or isinstance(other_policy, Operator):
            return ExpressionList(self, other_policy)
        if isinstance(other_policy, PolicySet):
            return CompoundPolicy(expression=self, policy_set=other_policy)
        if isinstance(other_policy, PolicyDict):
            return CompoundPolicy(expression=self, policy_dict=other_policy)
        if isinstance(other_policy, CompoundPolicy):
            return other_policy.add_expression(self)

    def __repr__(self):
        return json.dumps(self.configuration)

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
        if isinstance(other_policy, Expression or isinstance(other_policy, Operator)):
            return self.add(other_policy)
        if isinstance(other_policy, PolicySet):
            return CompoundPolicy(expression=self, policy_set=other_policy)
        if isinstance(other_policy, PolicyDict):
            return CompoundPolicy(expression=self, policy_dict=other_policy)
        if isinstance(other_policy, CompoundPolicy):
            return other_policy.add_expression_list(self)

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
        if len(args) == 0:
            return False
        key = args[0]
        return key in self.allowed

    def sum_with(self, other_policy):
        if (
            isinstance(other_policy, PolicyBoolean)
            or isinstance(other_policy, Expression)
            or isinstance(other_policy, Operator)
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
        if len(args) == 0:
            return False
        key = args[0]
        policy = self.policies.get(key, POLICY_FALSE)
        if len(args) > 1:
            return policy.should_allow(*args[1:], **kwargs)
        else:
            return policy.should_allow(**kwargs)

    def sum_with(self, other_policy):
        if (
            isinstance(other_policy, PolicyBoolean)
            or isinstance(other_policy, Expression)
            or isinstance(other_policy, Operator)
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

    def add_expression_list(self, expression_list):
        return CompoundPolicy(
            policy_dict=self.policy_dict,
            expressions=self.expressions.sum_with(expression_list),
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
            ret["expressions"] = self.expressions.to_json()
        if self.policy_dict is not None and self.policy_dict.keys():
            ret["policy_dict"] = self.policy_dict.to_json()
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
    """Build a complete policy for a RBAC context"""
    if isinstance(json_policy, bool):
        return policy_from_bool(json_policy)
    elif isinstance(json_policy, str):
        return PolicySet(json_policy)
    elif isinstance(json_policy, list):
        return policy_from_action_policy_list(json_policy)
    elif isinstance(json_policy, dict) and "condition" in json_policy:
        return policy_from_condition(json_policy)
    elif isinstance(json_policy, dict):
        return PolicyDict(
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
    ActionCondition: { String::ActionName: String::Expr }
    ResourcePolicyList: [ (String::ResourceName | ResourceCondition)+ ]
    ResourcePolicyDict: { (String::ResourceName: (Bool | String::Expr))+ }
    ResourceCondition: { String::ResourceName: String::Expr | OperatorConfig }
    Condition: { 'condition': String::Expr | OperatorConfig }
    OperatorConfig: { 'operator': String::OperatorName, additionalProperties... }
    ```
    """
    if isinstance(json_policy, bool):
        return policy_from_bool(json_policy)
    elif isinstance(json_policy, str):
        return PolicySet(json_policy)
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
            return PolicySet(x)
        else:
            return policy_from_action_condition(x)

    total = PolicySet()
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
            return PolicySet(x)
        elif isinstance(x, dict) and "condition" in x:
            return policy_from_condition(x)
        elif isinstance(x, list):
            return policy_from_resource_policy_list(x)
        elif isinstance(x, dict):
            return policy_from_resource_policy_dict(x)
        else:
            raise Exception(f"Invalid action policy dictionary value {x}")

    return PolicyDict({key: as_policy(value) for key, value in policy_dict.items()})


def policy_from_action_condition(action_condition):
    """
    ```
    ActionCondition: { String::ActionName: String::Expr }
    ```
    """
    return PolicyDict(
        {key: Expression(value) for key, value in action_condition.items()}
    )


def policy_from_resource_policy_list(policy_list):
    """
    ```
    ResourcePolicyList: [ (String::ResourceName | ResourceCondition)+ ]
    ```
    """

    def as_policy(x):
        if isinstance(x, str):
            return PolicySet(x)
        else:
            return policy_from_resource_condition(x)

    total = PolicySet()
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

    return PolicyDict({key: as_policy(value) for key, value in policy_dict.items()})


def policy_from_resource_condition(resource_condition):
    """
    ```
    ResourceCondition: { String::ResourceName: String::Expr | OperatorConfig }
    ```
    """
    if isinstance(resource_condition, str):
        return PolicyDict(
            {key: Expression(value) for key, value in resource_condition.items()}
        )
    elif isinstance(resource_condition, dict) and "operator" in resource_condition:
        return Operator(resource_condition)


def policy_from_condition(condition):
    """
    ```
    Condition: { 'condition': String::Expr |  }
    ```
    """
    condition_value = condition.get("condition")
    if isinstance(condition_value, str):
        return Expression(condition_value)
    elif isinstance(condition_value, dict) and "operator" in condition_value:
        return Operator(condition_value)


def policy_from_bool(b):
    if b:
        return POLICY_TRUE
    else:
        return POLICY_FALSE


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
