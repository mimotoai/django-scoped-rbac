from django.conf import settings
from rest_framework.settings import import_from_string


DEFAULTS = {
    "POLICY_FOR_AUTHENTICATED": "scoped_rbac.policy.POLICY_FALSE",
    "POLICY_FOR_STAFF": "scoped_rbac.policy.POLICY_FALSE",
    "POLICY_FOR_UNAUTHENTICATED": "scoped_rbac.policy.POLICY_FALSE",
}

IMPORT_STRINGS = ["POLICY_FOR_UNAUTHENTICATED", "POLICY_FOR_STAFF", ]


def scoped_rbac_settings():
    return getattr(settings, "SCOPED_RBAC", dict())


def import_policy_or_func(setting):
    default = DEFAULTS[setting]
    policy_or_func = scoped_rbac_settings().get(setting, default)
    if isinstance(policy_or_func, str):
        policy_or_func = import_from_string(policy_or_func, setting)
        if callable(policy_or_func):
            policy_or_func = policy_or_func()
    return policy_or_func


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
    return import_policy_or_func("POLICY_FOR_UNAUTHENTICATED")


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
    return import_policy_or_func("POLICY_FOR_AUTHENTICATED")


def policy_for_staff():
    """The default policy for staff users may be defined via settings. The value in
    settings may be ether a Policy instance or a string fully qualified name of a
    function that returns a Policy instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
         "POLICY_FOR_STAFF": "my_app.default_policy_for_staff"
       }
    """
    return import_policy_or_func("POLICY_FOR_STAFF")
