from .fixtures import superuser, staff_user, editor_user, not_authorized_user 
import os
import sys


def pytest_addoption(parser):
    parser.addoption(
        "--no-pkgroot",
        action="store_true",
        default=False,
        help="Remove package root directory from sys.path, ensuring that "
        "rest_framework is imported from the installed site-packages. "
        "Used for testing the distribution.",
    )


def pytest_configure(config):
    from django.conf import settings

    settings.configure(
        DEBUG_PROPAGATE_EXCEPTIONS=True,
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        SITE_ID=1,
        SECRET_KEY="not very secret in tests",
        USE_I18N=True,
        USE_L10N=True,
        STATIC_URL="/static/",
        ROOT_URLCONF="tests.urls",
        TEMPLATE_LOADERS=(
            "django.template.loaders.filesystem.Loader",
            "django.template.loaders.app_directories.Loader",
        ),
        MIDDLEWARE=(
            "django.middleware.common.CommonMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
        ),
        INSTALLED_APPS=(
            "django.contrib.admin",
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
            "django.contrib.sites",
            "django.contrib.messages",
            "django.contrib.staticfiles",
            "django_jsonfield_backport",
            "rest_framework",
            "rest_framework.authtoken",
            "scoped_rbac",
            "tests",
        ),
        PASSWORD_HASHERS=(
            "django.contrib.auth.hashers.SHA1PasswordHasher",
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
            "django.contrib.auth.hashers.BCryptPasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
            "django.contrib.auth.hashers.CryptPasswordHasher",
        ),
        REST_FRAMEWORK={
            "DEFAULT_PERMISSION_CLASSES": [
                "scoped_rbac.permissions.IsAuthorized",
            ],
        },
        SCOPED_RBAC={
            "POLICY_FOR_UNAUTHENTICATED": "tests.policy.policy_for_unauthenticated",
            "POLICY_FOR_STAFF": "tests.policy.policy_for_staff",
        },
    )

    try:
        import oauth_provider  # noqa
        import oauth2  # noqa
    except ImportError:
        pass
    else:
        settings.INSTALLED_APPS += ("oauth_provider",)

    try:
        import provider  # noqa
    except ImportError:
        pass
    else:
        settings.INSTALLED_APPS += ("provider", "provider.oauth2")

    # guardian is optional
    try:
        import guardian  # noqa
    except ImportError:
        pass
    else:
        settings.ANONYMOUS_USER_ID = -1
        settings.AUTHENTICATION_BACKENDS = (
            "django.contrib.auth.backends.ModelBackend",
            "guardian.backends.ObjectPermissionBackend",
        )
        settings.INSTALLED_APPS += ("guardian",)

    if config.getoption("--no-pkgroot"):
        sys.path.pop(0)

        # import scoped_rbac before pytest re-adds the package root directory.
        import scoped_rbac  # noqa

        package_dir = os.path.join(os.getcwd(), "scoped_rbac")
        assert not scoped_rbac.__file__.startswith(package_dir)

    try:
        import django  # noqa

        django.setup()
    except AttributeError:
        pass
