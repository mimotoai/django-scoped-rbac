from collections import namedtuple
from dataclasses import dataclass

Action = namedtuple("Action", "iri display_name, description")


@dataclass
class ResourceType:
    iri: str
    display_name: str
    description: str

    @property
    def list_iri(self) -> str:
        return f"{self.iri}/list"


class RbacRegistry:
    ACTIONS = list()
    CACHED_RESOURCE_TYPES = list()

    _processed_model_classes = False
    _ACCESS_CONTROLLED_MODEL_CLASSES = list()

    @classmethod
    def known_resource_types(cls):
        if not cls._processed_model_classes:
            cls._processed_model_classes = True
            for model_cls in cls._ACCESS_CONTROLLED_MODEL_CLASSES:
                if not model_cls._meta.abstract:
                    if not hasattr(model_cls, "resource_type"):
                        raise Exception(
                            "Subclasses of AccessControlled **MUST** have a "
                            f"`resource_type: ResourceType` property. {model_cls}"
                        )
                    cls.CACHED_RESOURCE_TYPES.append(model_cls.resource_type)
        return cls.CACHED_RESOURCE_TYPES


def register_access_controlled_model(cls):
    RbacRegistry._ACCESS_CONTROLLED_MODEL_CLASSES.append(cls)


def register_resource_types(*args: list[ResourceType]):
    RbacRegistry.CACHED_RESOURCE_TYPES.extend(args)


def register_actions(*actions: list[Action]):
    RbacRegistry.ACTIONS.extend(*actions)
