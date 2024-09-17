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

        self.data = apdu[5:]

    @property
    def next(self):
        return Response

    def __str__(self):
        string = "\n".join([
            "=" * 120,
            f"=> {self.apdu.hex()}"
        ])
        if len(self.data) != self.len:
            string = "\n".join([
                string,
                f"/!\\ Mismatch between advertised length {self.len} and actual length {len(self.data)}"
            ])
        return string


class Response:
    def __init__(self, data: bytes):
        self.rapdu = data
        self.code = int.from_bytes(data[-2:], 'big')
        self.data = data[:-2]

    def __str__(self):
        return "\n".join([
            "-" * 120,
            f"<= {self.rapdu.hex()}"
        ])


class Factory:
    def is_recognized(self, data: bytes, hint_chaining: bool) -> (bool, bool):
        return (True, False)

    def translate_command(self, data: bytes) -> Command:
        return Command(data)


@dataclass(frozen=True)
class APDUPair:
    command: Command
    response: Optional[Response]

    def __str__(self):
        return '\n'.join([
            str(self.command),
            str(self.response) if self.response else 'No response to this command'
        ])
