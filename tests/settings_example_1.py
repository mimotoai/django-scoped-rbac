def func1(x: str, y: str) -> bool:
    return False


DEFAULTS_1 = {
    "POLICY_FOR_UNAUTHENTICATED": "tests.settings_example_1.STRING_IMPORTED_DEFAULTS_1",
    "POLICY_FOR_AUTHENTICATED": {
        "": {
            "GET": ["DEFAULTS_1_AUTHENTICATED"],
        }
    },
    "POLICY_FOR_STAFF": lambda: {"": {"GET": "DEFAULTS_1_STAFF"}},
    "CEL_FUNCTIONS": {"func1": "tests.settings_example_1.func1"},
    "OPERATORS": {"operator1": object()},
}

STRING_IMPORTED_DEFAULTS_1 = {"": {"GET": ["DEFAULTS_1_UNAUTHENTICATED"]}}
