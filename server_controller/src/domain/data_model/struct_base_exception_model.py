from dataclasses import dataclass, field
from typing import Type
from datetime import date, time

from src.share import get_current_date, get_current_time


@dataclass(frozen=True, slots=True)
class StructBaseExceptionModel:
    instance: str
    exception: Type[BaseException]
    message: str
    created_date: date = field(default_factory=get_current_date)
    created_time: time = field(default_factory=get_current_time)
