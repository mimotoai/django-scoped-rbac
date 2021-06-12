DEFAULTS_1 = {
    "POLICY_FOR_UNAUTHENTICATED": "tests.settings_example_1.STRING_IMPORTED_DEFAULTS_1",
    "POLICY_FOR_AUTHENTICATED": {
        "": {
            "GET": [ "DEFAULTS_1_AUTHENTICATED" ],
        }
    },
    "POLICY_FOR_STAFF": lambda: {"": { "GET": "DEFAULTS_1_STAFF" }},
    "CEL_FUNCTIONS": {"func1": lambda x,y: False},
    "OPERATORS": {"operator1": object()},
}

STRING_IMPORTED_DEFAULTS_1 = {
    "": {
        "GET": ["DEFAULTS_1_UNAUTHENTICATED"]
    }
}
