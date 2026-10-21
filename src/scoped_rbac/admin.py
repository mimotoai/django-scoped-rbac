from django.contrib import admin

from .models import Role, RoleAssignment


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin): ...


@admin.register(RoleAssignment)
class RoleAssignmentAdmin(admin.ModelAdmin): ...
