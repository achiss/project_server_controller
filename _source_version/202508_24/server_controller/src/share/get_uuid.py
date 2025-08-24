from typing import overload
from uuid import UUID, uuid4, uuid5


@overload
def get_uuid() -> UUID: ...


@overload
def get_uuid(object_data: str,
             object_domain: UUID) -> UUID: ...


def get_uuid(object_data: str = None,
             object_domain: UUID = None) -> UUID:

    if not (object_data or object_domain):
        return uuid4()

    return uuid5(name=object_data, namespace=object_domain)
