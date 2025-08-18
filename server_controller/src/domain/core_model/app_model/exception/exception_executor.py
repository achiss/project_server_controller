from typing import Type

from src.domain.core_model.base_model import BaseExceptionModel


class ExceptionExecutor(BaseExceptionModel):
    def __init__(self, original_exception: Type[BaseException] | None, message: str) -> None:
        super().__init__(self.__class__.__name__, original_exception, message)
