from typing import TypeAlias, Type, List
from subprocess import CalledProcessError, CompletedProcess, run

E: TypeAlias = Type['ExceptionObject']
T: TypeAlias = int | E


def run_command(command: List[str] | str,
                message_func: str,
                message_unexpected: str,
                message_runtime: str,
                exception_object: E,
                is_check_process: bool = False) -> T:

    try:
        _result: CompletedProcess = run(
            command, shell=isinstance(command, str), check=True, capture_output=True, text=True)
        if is_check_process and _result.stderr:
            _message: str = message_runtime.format(message_func, _result.stderr)
            return _message, RuntimeError

        return _result.returncode

    except CalledProcessError as e:
        _message: str = message_runtime.format(message_func, e.stderr)
        return _message, RuntimeError

    except Exception as e:
        _message: str = message_unexpected.format(message_func, e)
        return _message, type(e)
