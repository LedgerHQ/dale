from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class INS:
    value: int
    name: str


class Command:
    def __init__(self, data: bytes):
        self.cla = data[0]
        self.ins = data[1]
        self.p1 = data[2]
        self.p2 = data[3]
        if len(data) == 4:
            self.len = 0
        else:
            self.len = data[4]
        if self.len == 0:
            self.data = b''
        else:
            self.data = data[5:]
        assert len(self.data) == self.len
    @property
    def next(self):
        return Response

class Response:
    def __init__(self, data: bytes):
        self.code = int.from_bytes(data[-2:], 'big')
        self.data = data[:-2]

@dataclass(frozen=True)
class APDUPair:
    command: Command
    response: Optional[Response]
    def __str__(self):
        return '\n'.join([
            str(self.command),
            str(self.response) if self.response else 'No response to this command'
        ])
