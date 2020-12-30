from datetime import datetime
from drf_scrud.serializers import EnvelopeCollectionSerializer, EnvelopeItemSerializer
from rest_framework import serializers
from rest_framework.reverse import reverse
from .models import ExampleAccessControlledModel
import hashlib


class ExampleAccessControlledModelSerializer(
    EnvelopeItemSerializer, serializers.HyperlinkedModelSerializer
):
    class Meta:
        model = ExampleAccessControlledModel
        fields = ("id", "name")
        list_serializer_class = EnvelopeCollectionSerializer

    def absolute_url_for(self, item):
        return reverse("exampleaccesscontrolledmodel-detail", args=[item.pk])

    @classmethod
    def etag_for(cls, item=None, *arg, pk=None, **kwarg):
        if pk is not None:
            item = ExampleAccessControlledModel.objects.get(pk=pk)
        return hashlib.md5(f"{item.name} {item.updated_at}".encode("utf-8")).hexdigest()

    @classmethod
    def last_modified_for(cls, item=None, *arg, pk=None, **kwarg):
        if pk is not None:
            item = ExampleAccessControlledModel.objects.get(pk=pk)
        return item.updated_at

    @classmethod
    def collection_last_modified(cls, request, *args, **kwargs):
        try:
            return ExampleAccessControlledModel.objects.latest().updated_at
        except ExampleAccessControlledModel.DoesNotExist:
            return datetime.now()

    @classmethod
    def collection_etag(cls, request, *args, **kwargs):
        try:
            return hashlib.md5(
                f"examplerbaccontext-list {ExampleAccessControlledModel.objects.latest().updated_at}".encode(
                    "utf-8"
                )
            ).hexdigest()
        except ExampleAccessControlledModel.DoesNotExist:
            return hashlib.md5(
                f"examplerbaccontext-list {datetime.now()}".encode("utf-8")
            ).hexdigest()
