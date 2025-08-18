from src.domain_server_controller.core_model.base_model import BaseExceptionModel


class ExceptionExecutingCommand(BaseExceptionModel):
    __slots__ = ()

    def __init__(self, original_exception: 'Type[BaseExceptionModel] | None', exception_message: str) -> None:
        super().__init__(self.__class__, original_exception, exception_message)


if __name__ == '__main__':
    _ex = ExceptionExecutingCommand(ValueError, 'test')
    print(_ex)