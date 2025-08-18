from typing import Callable


class HostOSHandler:
    __slots__ = ('run_command',)

    @staticmethod
    def update() -> True: print(True)
