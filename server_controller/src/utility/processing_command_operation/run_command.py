from typing import TypeAlias, Type
from subprocess import run

T: TypeAlias = Type[RuntimeError] | None


def run_command(command: str,
                is_check_error: bool) -> T:

    _result = run(command, shell=True, check=True, capture_output=True)
    if is_check_error and _result.stderr:
        return RuntimeError

    return None
