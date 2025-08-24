from abc import ABC, abstractmethod
from typing import Type


class IBaseExceptionModel(ABC, BaseException):
    __slots__ = ()

    @property
    @abstractmethod
    def instance(self) -> str: ...

    @property
    @abstractmethod
    def exception(self) -> Type[BaseException] | None: ...

    @property
    @abstractmethod
    def message(self) -> str: ...

    @property
    @abstractmethod
    def timestamp(self) -> str: ...

    @abstractmethod
    def display(self) -> None: ...
