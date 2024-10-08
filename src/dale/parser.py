import logging

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Tuple, Type, List

from dale.base import APDUPair, Command, Factory


class APDUParser(ABC):
    def __init__(self, factories: List[Factory]):
        self._factories = factories

    @abstractmethod
    def is_command(self, line) -> bool:
        pass

    @abstractmethod
    def is_response(self, line) -> bool:
        pass

    @abstractmethod
    def is_comment(self, line) -> bool:
        pass


class DefaultAPDUParser(APDUParser):
    _c = "=>"
    _r = "<="
    _cm = "#"

    def __init__(self, factories: List[Factory]):
        super().__init__(factories)
        self._pending: Optional[Command] = None
        self._conversation: List[APDUPair] = list()
        self._hint_chaining = False

    @property
    def conversation(self) -> Tuple[APDUPair, ...]:
        return tuple(self._conversation)

    def is_command(self, line) -> bool:
        return line.startswith(self._c)

    def is_response(self, line) -> bool:
        return line.startswith(self._r)

    def is_comment(self, line) -> bool:
        return line.startswith(self._cm)

    def reset(self) -> None:
        self._conversation = list()

    def feed(self, line: str) -> Optional[APDUPair]:
        pair: Optional[APDUPair] = None
        if self.is_command(line):
            if self._pending:
                pair = APDUPair(self._pending, None)
            try:
                data = bytes.fromhex(line.split(self._c)[1])
                if len(data) < 5:
                    logging.warning(f"Invalid command with only {len(data)} bytes, header is 5")
                else:
                    for f in self._factories:
                        (is_claimed, hint_chaining) = f.is_recognized(data=data, hint_chaining=self._hint_chaining)
                        if is_claimed:
                            self._hint_chaining = hint_chaining
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
        elif self.is_comment(line):
            pass
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
