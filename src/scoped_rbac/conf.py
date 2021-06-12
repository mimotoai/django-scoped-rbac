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
    of a Policy instance or a function that returns a Policy instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
            "POLICY_FOR_UNAUTHENTICATED": "my_app.default_policy_for_unauthenticated",
         ...
       }
    """
    return scoped_rbac_settings().policy_for_unauthenticated


def policy_for_authenticated():
    """The base policy for authenticated users may be defined via settings. The value in
    settings may be either a Policy instance or a string fully qualified name of a
    Policy instance or function that returns a Policy instance. For example:

    .. codeblock:: python

       SCOPED_RBAC = {
            "POLICY_FOR_AUTHENTICATED": "my_app.base_policy_for_authenticated",
         ...
       }
    """
    return scoped_rbac_settings().policy_for_authenticated


def policy_for_staff():
    """The default policy for staff users may be defined via settings. The value in
    settings may be either a Policy instance or a string fully qualified name of a
    Policy instance or a function that returns a Policy instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
           "POLICY_FOR_STAFF": "my_app.default_policy_for_staff"
       }
    """
    return scoped_rbac_settings().policy_for_staff


def cel_functions():
    """The registered CEL extension functions for use in CEL policy expressions. The
    value of the setting may be either a function or the string fully qualified name of
    a function that will be registered for use in CEL policy expressions. For example:

    .. code-block:: python

       SCOPED_RBAC = {
           "CEL_FUNCTIONS": {
               "is_allowed_transition": "myapp.workflow.is_allowed_transition",
           }
       }
    """
    return scoped_rbac_settings().cel_functions


def operators():
    """Policy operators to be registered for use as policy conditions. The value of the
    setting may be either a function that returns the operator or the string fully
    qualified name of an Operator instance or a function that returns an Operator
    instance. For example:

    .. code-block:: python

       SCOPED_RBAC = {
           "OPERATORS": {
               "is_allowed_transition": "myapp.workflow.allowed_transition_operator",
           }
       }
    """
    return scoped_rbac_settings().operators


class Settings:
    """Lazy loading and resolution of `scoped_rbac` settings."""
    def __init__(self, sources):
        self._sources = sources
        self._resolved_sources = None
        self._policy_for_unauthenticated = None
        self._policy_for_authenticated = None
        self._policy_for_staff = None
        self._cel_functions = None
        self._operators = None

    @property
    def policy_for_unauthenticated(self):
        if self._policy_for_unauthenticated is None:
            self._policy_for_unauthenticated = self.resolve_policy("POLICY_FOR_UNAUTHENTICATED")
        return self._policy_for_unauthenticated

    @property
    def policy_for_authenticated(self):
        if self._policy_for_authenticated is None:
            self._policy_for_authenticated = self.resolve_policy("POLICY_FOR_AUTHENTICATED")
        return self._policy_for_authenticated

    @property
    def policy_for_staff(self):
        if self._policy_for_staff is None:
            self._policy_for_staff = self.resolve_policy("POLICY_FOR_STAFF")
        return self._policy_for_staff

    @property
    def cel_functions(self):
        if self._cel_functions is None:
            self._cel_functions = self.resolve_dict_setting("CEL_FUNCTIONS")
            self._cel_functions.update(REGISTERED_CEL_FUNCTIONS)
        return self._cel_functions

    @property
    def operators(self):
        if self._operators is None:
            self._operators = self.resolve_dict_setting("OPERATORS")
            self._operators.update((REGISTERED_OPERATORS))
        return self._operators

    @property
    def sources(self):
        if self._resolved_sources is None:
            self._resolved_sources = [self.resolve_source(source) for source in self._sources]
        return self._resolved_sources

    def resolve_source(self, source):
        if isinstance(source, str):
            source = import_string(source)
        if callable(source):
            source = source()
        return source

    def resolve_policy(self, policy_key):
        from scoped_rbac.policy import POLICY_FALSE, Policy, policy_from_json, RootPolicy
        result = POLICY_FALSE
        for source in self.sources:
            value = source.get(policy_key, POLICY_FALSE)
            if isinstance(value, str):
                value = import_string(value)
            if callable(value):
                value = value()
            if not isinstance(value, Policy):
                value = policy_from_json(value)

            if isinstance(value, RootPolicy):
                breakpoint()
                result = result.sum_with(value.policy)
            else:
                result = result.sum_with(value)
        return result

    def resolve_dict_setting(self, setting_key):
        result = {}
        for source in self.sources:
            value = source.get(setting_key, {})
            if isinstance(value, str):
                value = import_string(value)
            if callable(value):
                value = value()
            result.update(value)
        return result


RESOLVED_SETTINGS = None


def scoped_rbac_settings():
    global RESOLVED_SETTINGS
    if RESOLVED_SETTINGS is None:
        retrieved_settings = getattr(settings, "SCOPED_RBAC", dict())
        retrieved_settings = resolve_scoped_rbac_settings(retrieved_settings)
        if not isinstance(retrieved_settings, list):
            retrieved_settings = [retrieved_settings]
        RESOLVED_SETTINGS = Settings(retrieved_settings)
    return RESOLVED_SETTINGS


def resolve_scoped_rbac_settings(retrieved_settings):
    if isinstance(retrieved_settings, str):
        retrieved_settings = import_string(retrieved_settings)
    if callable(retrieved_settings):
        retrieved_settings = retrieved_settings()

    if isinstance(retrieved_settings, list):
        retrieved_settings = [import_string(source) for source in retrieved_settings]
    else:
        retrieved_settings = [retrieved_settings]
    return retrieved_settings


REGISTERED_CEL_FUNCTIONS = {}


def register_cel_function(name, func):
    global REGISTERED_CEL_FUNCTIONS
    REGISTERED_CEL_FUNCTIONS[name] = func


REGISTERED_OPERATORS = {}


def register_operator(name, func):
    global REGISTERED_OPERATORS
    REGISTERED_OPERATORS[name] = func
