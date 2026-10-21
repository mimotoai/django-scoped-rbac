import logging
from dataclasses import dataclass
from pprint import pformat

import pytest
from django.contrib.auth.models import User
from faker import Faker
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from safetydance import step, step_data

# from safetydance_django.steps import *
from safetydance_django.test import *
from safetydance_test import And, Given, TestStepPrefix, Then, When, scripted_test

from scoped_rbac.models import Role
from tests.rest import ExampleMultipleContextsModelViewSet

role_url = step_data(str)
multiple_contexts_editor_url = step_data(str)
multiple_contexts_reader_url = step_data(str)


@step
def role(role_json):
    if role_json is None:
        return
    When.http.post(
        reverse("role-list"),
        role_json,
        format="json",
    )
    logging.info(http_response)
    logging.info(http_response.data)
    Then.http.status_code_is(201)
    role_url = http_response["location"]


@step
def create_editor_role(context_url):
    role(
        {
            "definition": {
                "http.POST": [Role.resource_type.iri],
                "http.GET": [Role.resource_type.iri, Role.resource_type.list_iri],
                "http.PUT": [Role.resource_type.iri],
                "http.DELETE": [Role.resource_type.iri],
            },
            # TODO add these fields
            # "name": role_name,
            # "description": role_description,
            "rbac_context": context_url,
        }
    )


@step
def multiple_contexts_editor_role():
    role(
        {
            "definition": {
                "http.POST": ExampleMultipleContextsModelViewSet.type_iri,
                "http.GET": [
                    ExampleMultipleContextsModelViewSet.type_iri,
                    f"{ExampleMultipleContextsModelViewSet.type_iri}/list",
                ],
                "http.PUT": ExampleMultipleContextsModelViewSet.type_iri,
                "http.DELETE": ExampleMultipleContextsModelViewSet.type_iri,
            },
            "rbac_context": "",
        }
    )
    multiple_contexts_editor_url = role_url


@step
def multiple_contexts_reader_role():
    role(
        {
            "definition": {
                "http.GET": [
                    ExampleMultipleContextsModelViewSet.type_iri,
                    f"{ExampleMultipleContextsModelViewSet.type_iri}/list",
                ],
            },
            "rbac_context": "",
        }
    )
    multiple_contexts_reader_url = role_url


@step
def get_role_list():
    When.http.get(reverse("role-list"))
    Then.http.status_code_is(200)


@step
def role_list_contains(*role_urls):
    list_json = http_response.json()
    urls = [x["url"] for x in list_json["results"]]
    for role_url in role_urls:
        assert role_url in urls, f"No matching role for {role_url} in {urls}"


@step
def role_list_does_not_contain(*role_urls):
    list_json = http_response.json()
    urls = [x["url"] for x in list_json["results"]]
    for role_url in role_urls:
        assert role_url not in urls, f"Found a matching role for {role_url} in {urls}"


@step
def assign_role(role_url, user, context_url):
    When.http.post(
        reverse("roleassignment-list"),
        {
            "user": reverse("user-detail", [user.instance.pk]),
            "role": role_url,
            "rbac_context": context_url,
        },
        format="json",
    )
    Then.http.status_code_is(201)


@step
def get_user_rbac_policy():
    When.http.get(reverse("user-rbac-policy"), format="json")


@step
def put_safe(*args, **kwargs):
    if "etag" in http_response._headers:
        kwargs["HTTP_IF_MATCH"] = http_response["etag"]
    if "last-modified" in http_response._headers:
        kwargs["HTTP_IF_UNMODIFIED_SINCE"] = http_response["last-modified"]
    http_response = http_client.put(*args, **kwargs)


@step
def delete_safe(*args, **kwargs):
    if "etag" in http_response._headers:
        kwargs["HTTP_IF_MATCH"] = http_response["etag"]
    if "last-modified" in http_response._headers:
        kwargs["HTTP_IF_UNMODIFIED_SINCE"] = http_response["last-modified"]
    http_response = http_client.delete(*args, **kwargs)
