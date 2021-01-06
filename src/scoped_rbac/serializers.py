from django.contrib.auth import get_user_model
from django.utils.timezone import now
from rest_framework import serializers
from uuid import uuid4
from .models import Role, RoleAssignment


class RoleSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Role
        # fields = ("definition", )
        fields = "__all__"

    etag = serializers.HiddenField(default=lambda: uuid4().hex)
    modified_at = serializers.HiddenField(default=now)


class RoleAssignmentSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = RoleAssignment
        # fields = ("user", "role", "resource_type", )
        fields = "__all__"

    etag = serializers.HiddenField(default=lambda: uuid4().hex)
    modified_at = serializers.HiddenField(default=now)


class UserSerializer(serializers.HyperlinkedModelSerializer):
    """User Serialization"""

    class Meta:
        model = get_user_model()
        fields = ("url", "username", "email", "first_name", "last_name", "id", )
