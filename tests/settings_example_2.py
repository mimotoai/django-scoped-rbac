def func2(x: str, y: str) -> bool:
    return False


DEFAULTS_2_ACTUAL = {
    "POLICY_FOR_UNAUTHENTICATED": "tests.settings_example_2.STRING_IMPORTED_DEFAULTS_2",
    "POLICY_FOR_AUTHENTICATED": {
        "": {
            "GET": ["DEFAULTS_2_AUTHENTICATED"],
        }
    },
    "POLICY_FOR_STAFF": lambda: {"": {"GET": "DEFAULTS_2_STAFF"}},
    "CEL_FUNCTIONS": {"func2": "tests.settings_example_2.func2"},
    "OPERATORS": {"operator2": object()},
}

DEFAULTS_2_ACTUAL_CALLABLE = lambda: DEFAULTS_2_ACTUAL

DEFAULTS_2 = "tests.settings_example_2.DEFAULTS_2_ACTUAL_CALLABLE"

STRING_IMPORTED_DEFAULTS_2 = {"": {"GET": ["DEFAULTS_2_UNAUTHENTICATED"]}}
