from django.db import models

from scoped_rbac.models import AccessControlledModel
from scoped_rbac.registry import ResourceType


class ScopedRbacTestModel(models.Model):
    """Mixin class for models used in testing."""

    class Meta:
        app_label = "tests"
        abstract = True


class ExampleAccessControlledModel(ScopedRbacTestModel, AccessControlledModel):
    class Meta:
        get_latest_by = "updated_at"

    name = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    parent_context = models.ForeignKey("self", null=True, on_delete=models.CASCADE)

    resource_type = ResourceType(
        "rbac.ExampleAccessControlledModel",
        "ExampleAccessControlledModel",
        "An example AccessControlledModel for testing and demonstration purposes.",
    )


class ExampleWithMultipleContexts(ScopedRbacTestModel, models.Model):
    resource_type = ResourceType(
        "rbac.ExampleWithMultipleContexts",
        "ExampleWithMultipleContexts",
        "An example model with multiple contexts for test purposes",
    )

    context_1 = models.CharField(max_length=128, blank=True)
    context_2 = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def rbac_contexts(self):
        return [self.context_1, self.context_2]


class ExampleFolder(ScopedRbacTestModel, models.Model):
    """Holds the context for `ExampleDerivedContextModel`; not access controlled."""

    ctx = models.CharField(max_length=128, blank=True)


class ExampleDerivedContextModel(ScopedRbacTestModel, AccessControlledModel):
    """An access-controlled model whose `rbac_context` is derived in `save()`."""

    name = models.CharField(max_length=128, blank=True)
    folder = models.ForeignKey(ExampleFolder, on_delete=models.CASCADE)

    resource_type = ResourceType(
        "rbac.ExampleDerivedContextModel",
        "ExampleDerivedContextModel",
        "An example model whose rbac_context is derived from its folder in save().",
    )

    def save(self, *args, **kwargs):
        self.rbac_context = self.folder.ctx
        super().save(*args, **kwargs)


class ExampleContextTag(ScopedRbacTestModel, models.Model):
    ctx = models.CharField(max_length=128, blank=True)


class ExampleTaggedContextsModel(ScopedRbacTestModel, models.Model):
    """A model whose `rbac_contexts` come from a many-to-many relation."""

    tags = models.ManyToManyField(ExampleContextTag, blank=True)

    resource_type = ResourceType(
        "rbac.ExampleTaggedContextsModel",
        "ExampleTaggedContextsModel",
        "An example model whose rbac_contexts come from many-to-many tags.",
    )

    @property
    def rbac_contexts(self):
        return [tag.ctx for tag in self.tags.all()]
