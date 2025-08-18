from src.share.utility import ProcessorCommand

from src.service.command_executor.operation.host_os_handler import HostOSHandler


class CommandExecutor:
    __slots__ = ('os', 'package',)

    def __init__(self) -> None:
        self.os = HostOSHandler
        self.package = None


if __name__ == '__main__':
    _cmd_executor = CommandExecutor()
    _cmd_executor.os.update()
