from django.conf import settings
from django.utils.module_loading import import_string
from rest_framework.settings import import_from_string


DEFAULTS = {
    "POLICY_FOR_AUTHENTICATED": "scoped_rbac.policy.POLICY_FALSE",
    "POLICY_FOR_STAFF": "scoped_rbac.policy.POLICY_FALSE",
    "POLICY_FOR_UNAUTHENTICATED": "scoped_rbac.policy.POLICY_FALSE",
    "CEL_FUNCTIONS": None,
    "OPERATORS": None,
}


def policy_for_unauthenticated():
    """The default policy for unauthenticated users may be defined via settings. The
    value in settings may be either a Policy instance or a string fully qualified name
    of a function that returns a Policy instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
            "POLICY_FOR_UNAUTHENTICATED": "my_app.default_policy_for_unauthenticated",
         ...
       }
    """
    return import_obj_or_func("POLICY_FOR_UNAUTHENTICATED", default_policies_from)


def policy_for_authenticated():
    """The base policy for authenticated users may be defined via settings. The value in
    seetgings may be either a Policy instance or a string fully qualified name of a
    function that returns a Policy instance. For example:

    .. codeblock:: python

       SCOPED_RBAC = {
            "POLICY_FOR_AUTHENTICATED": "my_app.base_policy_for_authenticated",
         ...
       }
    """
    return import_obj_or_func("POLICY_FOR_AUTHENTICATED", default_policies_from)


def policy_for_staff():
    """The default policy for staff users may be defined via settings. The value in
    settings may be ether a Policy instance or a string fully qualified name of a
    function that returns a Policy instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
           "POLICY_FOR_STAFF": "my_app.default_policy_for_staff"
       }
    """
    return import_obj_or_func("POLICY_FOR_STAFF", default_policies_from)


def cel_functions():
    global RETRIEVED_CONFIGURED_CEL_FUNCTIONS
    global REGISTERED_CEL_FUNCTIONS
    if not RETRIEVED_CONFIGURED_CEL_FUNCTIONS:
        RETRIEVED_CONFIGURED_CEL_FUNCTIONS = True
        configured_cel_functions = import_obj_or_func("CEL_FUNCTIONS", dict_imports_from)
        if configured_cel_functions is not None:
            REGISTERED_CEL_FUNCTIONS.extend(configured_cel_functions)
    return REGISTERED_CEL_FUNCTIONS


def operators():
    global REGISTERED_OPERATORS
    global RETRIEVED_CONFIGURED_OPERATORS
    if not RETRIEVED_CONFIGURED_OPERATORS:
        RETRIEVED_CONFIGURED_OPERATORS = True
        configured_operators = import_obj_or_func("OPERATORS", dict_imports_from)
        if configured_operators is not None:
            REGISTERED_OPERATORS.extend(configured_operators)
    return REGISTERED_OPERATORS


def scoped_rbac_settings():
    return getattr(settings, "SCOPED_RBAC", dict())


def import_obj_or_func(setting, list_handler=None):
    default = DEFAULTS[setting]
    policy_obj = scoped_rbac_settings().get(setting, default)
    if isinstance(policy_obj, str):
        policy_obj = import_from_string(policy_obj, setting)
        if callable(policy_obj):
            policy_obj = policy_obj()
    elif isinstance(policy_obj, list) and list_handler is not None:
            policy_obj = list_handler(policy_obj)
    return policy_obj


def default_policies_from(*policies_to_import):
    """From a list of configuration dictionaries defined in referenced applications,
    construct a total configuration dictionary for all `SCOPED_RBAC` defaults.
    
    Here's an example of configuring `SCOPED_RBAC` in a Django settings module:
    .. codeblock:: python3
       
       SCOPED_RBAC = default_policies_from(
           "my_django_app.RBAC_DEFAULTS",
           "my_django_app.apps.app1.RBAC_DEFAULTS",
           "my_django_app.apps.app2.RBAC_DEFAULTS",
       )
    """
    total_policies = {
        "POLICY_FOR_UNAUTHENTICATED": None,
        "POLICY_FOR_AUTHENTICATED": None,
        "POLICY_FOR_STAFF": None,
    }
    for policy_to_import in policies_to_import:
        default_policy = import_string(policy_to_import)
        if callable(default_policy):
            default_policy = default_policy()
        for policy_name in ["POLICY_FOR_UNAUTHENTICATED", "POLICY_FOR_AUTHENTICATED", "POLICY_FOR_STAFF"]:
            additional_policy = default_policy.get(policy_name, None)
            if isinstance(additional_policy, str):
                additional_policy = import_string(additional_policy)
            if isinstance(additional_policy, callable):
                additional_policy = additional_policy()
            current_policy = total_policies[policy_name]
            if current_policy is None:
                total_policies[policy_name] = additional_policy
            else:
                total_policies[policy_name] = current_policy.sum_with(additional_policy)
    return total_policies


def dict_imports_from(*dicts_to_import):
    total = {}
    for dict_to_import in dicts_to_import:
        if isinstance(dict_to_import, str):
            dict_to_import = import_string(dict_to_import)
        if isinstance(dict_to_import, callable):
            dict_to_import = dict_to_import()
        total.extend(dict_to_import)
    return total


REGISTERED_CEL_FUNCTIONS = {}
RETRIEVED_CONFIGURED_CEL_FUNCTIONS = False


def register_cel_function(name, func):
    global REGISTERED_CEL_FUNCTIONS
    REGISTERED_CEL_FUNCTIONS[name] = func


REGISTERED_OPERATORS = {}
RETRIEVED_CONFIGURED_OPERATORS = None


def register_operator(name, func):
    global REGISTERED_OPERATORS
    REGISTERED_OPERATORS[name] = func
