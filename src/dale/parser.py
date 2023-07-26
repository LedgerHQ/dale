import logging

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Tuple, Type

from dale.base import APDUPair, Response, Command, Factory
from dale.exchange import ExchangeFactory


class APDUParser(ABC):
    def __init__(self, factories: Factory):
        self._factories = factories
    @abstractmethod
    def is_command(self, line) -> bool:
        pass
    @abstractmethod
    def is_response(self, line) -> bool:
        pass

class DefaultAPDUParser(APDUParser):
    _c = "=>"
    _r = "<="

    def __init__(self, factories: Factory):
        super().__init__(factories)
        self._pending: Optional[Command] = None
        self._conversation = list()
        self._last_factory = None

    @property
    def conversation(self) -> Tuple[APDUPair]:
        return tuple(self._conversation)

    def is_command(self, line) -> bool:
        return line.startswith(self._c)

    def is_response(self, line) -> bool:
        return line.startswith(self._r)

    def reset(self) -> None:
        self._conversation = list()

    def feed(self, line: str) -> Optional[APDUPair]:
        pair: Optional[APDUPair] = None
        if self.is_command(line):
            if self._pending:
                pair = APDUPair(self._pending, None)
            try:
                data = bytes.fromhex(line.split(self._c)[1])
                for f in self._factories:
                    if f.is_recognized(data=data, last_one_recognized = (self._last_factory == f)):
                        self._last_factory = f
                        self._pending = f.translate_command(data=data)
                        break
            except AssertionError as e:
                logging.exception(e)
                pass
        elif self.is_response(line):
            data = bytes.fromhex(line.split(self._r)[1])
            if self._pending:
                pair = APDUPair(self._pending, self._pending.next(data))
                self._pending = None
            else:
                logging.warning("Unexpected answer. Ignoring")
        else:
            logging.warning("Unknown line: %s", line)

        if pair is not None:
            self._conversation.append(pair)
            return pair
        return None

    def end(self) -> None:
        if self._pending is not None:
            self._conversation.append(APDUPair(self._pending, None))

    def __enter__(self) -> "DefaultAPDUParser":
        self.reset()
        return self

    def __exit__(
        self, exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        self.end()
