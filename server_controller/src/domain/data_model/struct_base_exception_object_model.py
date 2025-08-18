from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class StructBaseExceptionObjectModel:
    code: int
    data_in: Any
    data_ex: str
