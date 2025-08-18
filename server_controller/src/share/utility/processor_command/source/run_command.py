from typing import TypeAlias, Type, Tuple
from subprocess import run

T: TypeAlias = bool | Tuple[str, Type[Exception]]


def run_command(command: str,
                is_check_error: bool,
                message_func: str,
                message_unexpected: str,
                message_runtime: str) -> 'T':

    try:
        _result = run(command, shell=True, check=True, capture_output=True)
        if is_check_error and _result.stderr:
            _message: str = message_runtime.format(
                message_func,
                f'during ({command}) error - {_result.stderr}')
            return _message, RuntimeError

        return True

    except Exception as e:
        _message: str = message_unexpected.format(message_func, e)
        return _message, type(e)
