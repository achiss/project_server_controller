from typing import Type

from src.domain.interface import IBaseExceptionModel
from src.domain.data_model import StructBaseExceptionModel


class BaseExceptionModel(IBaseExceptionModel):
    __slots__ = ('__data',)

    def __init__(self, instance: str, original_exception: Type[BaseException] | None, message: str) -> None:
        self.__data = StructBaseExceptionModel(instance, original_exception, message)

    @property
    def instance(self) -> str: return self.__data.instance

    @property
    def exception(self) -> Type[BaseException] | None: return self.__data.exception

    @property
    def message(self) -> str: return self.__data.message

    @property
    def timestamp(self) -> str: return f'{self.__data.created_date} {self.__data.created_time}'

    def display(self) -> None: print(self.__str__())

    def __str__(self) -> str:
        if not self.exception:
            return self.__return_description_string()

        return self.__return_exception_string()

    def __return_exception_string(self) -> str:
        return (f'\nCustom exception: {self.instance}'
                f'\nOriginal exception: {self.exception.__name__}'
                f'\nException message: {self.message}'
                f'\nException timestamp: {self.timestamp}')

    def __return_description_string(self) -> str:
        return (f'\nInstance: {self.instance}'
                f'\nMessage: {self.message}'
                f'\nTimestamp: {self.timestamp}')
