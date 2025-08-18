from typing import Tuple, Type

from src.share.utility.processor_command.source import run_command
from data.message import MESSAGE_TYPE, MESSAGE_RUNTIME, MESSAGE_UNEXPECTED

from src.domain_server_controller.core_model.app_model.exception import ExceptionExecutingCommand as ExceptionCommand


_class_message: str = 'Operation executing command failed'


class ProcessorCommand:
    __slots__ = ()

    @staticmethod
    def run(operation_command: str,
            check_error: bool = True) -> None:

        if str != type(operation_command):
            _message: str = MESSAGE_TYPE.format(_class_message, 'str', type(operation_command).__name__)
            raise ExceptionCommand(
                original_exception=TypeError,
                exception_message=_message,
            )

        _result: bool | Tuple[str, Type[Exception]] = run_command(
            command=operation_command,
            is_check_error=check_error,
            message_func=_class_message,
            message_runtime=MESSAGE_RUNTIME,
            message_unexpected=MESSAGE_UNEXPECTED,
        )
        if bool == type(_result):
            return None

        raise ExceptionCommand(
            original_exception=_result[1],
            exception_message=_result[0],
        )
