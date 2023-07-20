from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class INS:
    value: int
    name: str


class Command:
    def __init__(self, apdu: bytes):
        self.apdu = apdu
        self.cla = apdu[0]
        self.ins = apdu[1]
        self.p1 = apdu[2]
        self.p2 = apdu[3]

        if len(apdu) == 4:
            self.len = 0
        else:
            self.len = apdu[4]

        if self.len == 0:
            self.data = b''
        else:
            self.data = apdu[5:]

        assert len(self.data) == self.len

    @property
    def next(self):
        return Response
    def __str__(self):
        return "\n".join([
            f"=> {self.apdu.hex()}"
        ])

class Response:
    def __init__(self, data: bytes):
        self.rapdu = data
        self.code = int.from_bytes(data[-2:], 'big')
        self.data = data[:-2]
    def __str__(self):
        return "\n".join([
            f"<= {self.rapdu.hex()}"
        ])

@dataclass(frozen=True)
class APDUPair:
    command: Command
    response: Optional[Response]
    def __str__(self):
        return '\n'.join([
            str(self.command),
            str(self.response) if self.response else 'No response to this command'
        ])
