from dataclasses import dataclass, field
from datetime import date, time


def get_date() -> date:

    from src.share.script import get_current_date

    return get_current_date()


def get_time() -> time:

    from src.share.script import get_current_time

    return get_current_time()


@dataclass(frozen=True, slots=True)
class BaseExceptionModel(Exception):
    instance: 'Type[BaseExceptionModel]'
    exception: 'Type[BaseException] | None'
    message: str
    created_date: date = field(default_factory=get_date)
    created_time: time = field(default_factory=get_time)

    def __return_exception_data(self) -> str:
        return (f'\nInstance: {self.instance.__name__}'
                f'\nOriginal exception: {self.exception.__name__}'
                f'\nException message: {self.message}'
                f'\nException timestamp: {self.created_date} {self.created_time}')

    def __return_data(self) -> str:
        return (f'\nInstance: {self.instance.__name__}'
                f'\nAction message: {self.message}'
                f'\nTimestamp: {self.created_date} {self.created_time}')

    def __str__(self) -> str:
        return BaseExceptionModel.__return_exception_data(self) if self.exception else BaseExceptionModel.__return_data(self)
