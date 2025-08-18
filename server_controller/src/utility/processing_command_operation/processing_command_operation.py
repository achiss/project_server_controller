from typing import Type

from src.utility.processing_command_operation.run_command import run_command
from data.message import MESSAGE_TYPE, MESSAGE_UNEXPECTED


def processing_command_operation(command: str,
                                 is_check_error: bool) -> bool:

    if str != type(command):
        _message: str = MESSAGE_TYPE.format()
        pass

    try:
        _result: Type[RuntimeError] | None = run_command(
            command=command,
            is_check_error=is_check_error,
        )

        if None != type(_result):
            return True

        return False

    except Exception as e:
        _message: str = MESSAGE_UNEXPECTED.format()
        pass
