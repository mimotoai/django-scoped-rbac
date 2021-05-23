from dataclasses import dataclass
from faker import Faker
import pytest


@dataclass
class TestUser:
    username: str
    email: str
    password: str
    instance: object


def create_user(user_model, is_super=False, is_staff=False):
    fake = Faker()
    name = fake.pystr(min_chars=10, max_chars=20)
    email = f"{name}@example.com"
    passwd = fake.pystr(min_chars=12, max_chars=20)
    if is_super:
        user = user_model.objects.create_superuser(name, email, passwd)
    else:
        user = user_model.objects.create(
            username=name,
            email=email,
            password=passwd,
            is_active=True,
            is_staff=is_staff,
        )
    user.save()
    return TestUser(name, email, passwd, user)


@pytest.fixture()
def superuser(transactional_db, django_user_model):
    return create_user(django_user_model, is_super=True)


@pytest.fixture()
def staff_user(transactional_db, django_user_model):
    return create_user(django_user_model, is_staff=True)


@pytest.fixture()
def editor_user(transactional_db, django_user_model):
    return create_user(django_user_model)


@pytest.fixture()
def not_authorized_user(transactional_db, django_user_model):
    return create_user(django_user_model)