import pytest
from django.contrib.auth.models import User
from django.test import TestCase
from faker import Faker

from scoped_rbac.models import Role, RoleAssignment
from scoped_rbac.registry import RbacRegistry
from tests.models import ExampleAccessControlledModel


class AccessControlledTestCase(TestCase):
    def test_registration_of_resource_types(self):
        for resource_type in (
            Role.resource_type,
            RoleAssignment.resource_type,
            ExampleAccessControlledModel.resource_type,
        ):
            assert resource_type in RbacRegistry.known_resource_types()
