import os
import sys
from collections.abc import Mapping

import pytest

from .fixtures import editor_user, not_authorized_user, staff_user, superuser

# Fixtures for the update-authorization tests. `.helpers` imports Django models, so
# it is imported lazily: this module is loaded before `pytest_configure` sets up
# Django.


@pytest.fixture
def user(django_user_model):
    """A user without grants; tests grant what they need."""
    return django_user_model.objects.create(username="context-a-admin")


@pytest.fixture
def ra_patcher_in_a(user):
    """`user` may PATCH and GET RoleAssignments in context A only; returns the
    user's own RoleAssignment (in A)."""
    from .helpers import RA, assign, make_role

    role = make_role({"http.PATCH": [RA], "http.GET": [RA]}, "A")
    return assign(user, role, "A")


@pytest.fixture
def read_replica():
    from .helpers import ReadReplicaRouter, installed_routers

    yield from installed_routers(ReadReplicaRouter())


@pytest.fixture
def other_database():
    from .helpers import OtherDatabaseRouter, installed_routers

    yield from installed_routers(OtherDatabaseRouter())


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
        # "other" and "replica" are separate in-memory databases for multi-database
        # tests. No routers are installed globally; tests opt in with
        # override_settings(DATABASE_ROUTERS=[...]). "replica" is deliberately not a
        # TEST MIRROR, so it never sees writes made to "default".
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
            "other": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
            "replica": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
        },
        SITE_ID=1,
        SECRET_KEY="not very secret in tests",
        USE_I18N=True,
        STATIC_URL="/static/",
        ROOT_URLCONF="tests.urls",
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
            "rest_framework",
            "rest_framework.authtoken",
            "scoped_rbac",
            "tests",
        ),
        PASSWORD_HASHERS=("django.contrib.auth.hashers.MD5PasswordHasher",),
        REST_FRAMEWORK={
            "DEFAULT_PERMISSION_CLASSES": [
                "scoped_rbac.permissions.IsAuthorized",
            ],
        },
        SCOPED_RBAC={
            "POLICY_FOR_UNAUTHENTICATED": "tests.policy.policy_for_unauthenticated",
            "POLICY_FOR_STAFF": "tests.policy.policy_for_staff",
            "OPERATORS": {
                # True for the resource `True`, and for a mapping whose "a" is 3 (so
                # that the merge property tests can see operators next to CEL).
                "istrue": lambda resource, configuration: (
                    resource == True
                    or (isinstance(resource, Mapping) and resource.get("a") == 3)
                ),
            },
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
