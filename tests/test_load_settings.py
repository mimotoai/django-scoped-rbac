from scoped_rbac.conf import resolve_scoped_rbac_settings, Settings
from scoped_rbac.policy import Permission


def test_resolve_scoped_rbac_settings():
    settings = Settings(resolve_scoped_rbac_settings([
        "tests.settings_example_1.DEFAULTS_1", "tests.settings_example_2.DEFAULTS_2"]))
    
    assert settings.policy_for_unauthenticated.should_allow("", *Permission("GET", "DEFAULTS_1_UNAUTHENTICATED"))
    assert settings.policy_for_authenticated.should_allow("", *Permission("GET", "DEFAULTS_1_AUTHENTICATED"))
    assert settings.policy_for_staff.should_allow("", *Permission("GET", "DEFAULTS_1_STAFF"))
    assert "func1" in settings.cel_functions
    assert "operator1" in settings.operators

    assert settings.policy_for_unauthenticated.should_allow("", *Permission("GET", "DEFAULTS_2_UNAUTHENTICATED"))
    assert settings.policy_for_authenticated.should_allow("", *Permission("GET", "DEFAULTS_2_AUTHENTICATED"))
    assert settings.policy_for_staff.should_allow("", *Permission("GET", "DEFAULTS_2_STAFF"))
    assert "func2" in settings.cel_functions
    assert "operator2" in settings.operators
