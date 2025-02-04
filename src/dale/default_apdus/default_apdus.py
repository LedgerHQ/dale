from dale.base import Command, Response, Factory
from typing import Tuple

from ..utils import lv_digest, l_digest
from ..display import summary, item_str


class DefaultClaIns:
    DEFAULT_APDU_INS_GET_VERSION        = (0xB0, 0x01)
    DEFAULT_APDU_INS_GET_SEED_COOKIE    = (0xB0, 0x02)
    DEFAULT_APDU_INS_STACK_CONSUMPTION  = (0xB0, 0x57)
    DEFAULT_APDU_INS_APPLICATION_EXIT   = (0xB0, 0xA7)
    DEFAULT_APDU_INS_APPLICATION_OPEN   = (0xE0, 0xD8)

    @classmethod
    def get_default_instructions(cls):
        return [
            cls.DEFAULT_APDU_INS_GET_VERSION,
            cls.DEFAULT_APDU_INS_GET_SEED_COOKIE,
            cls.DEFAULT_APDU_INS_STACK_CONSUMPTION,
            cls.DEFAULT_APDU_INS_APPLICATION_EXIT,
            cls.DEFAULT_APDU_INS_APPLICATION_OPEN,
        ]


def is_valid_default_ins(cla: int, ins: int) -> bool:
    for instruction in DefaultClaIns.get_default_instructions():
        if (cla, ins) == instruction:
            return True
    return False


def default_ins_to_text(cla: int, ins: int) -> str:
    instruction_map = {
        DefaultClaIns.DEFAULT_APDU_INS_GET_VERSION: "GET_VERSION",
        DefaultClaIns.DEFAULT_APDU_INS_GET_SEED_COOKIE: "GET_SEED_COOKIE",
        DefaultClaIns.DEFAULT_APDU_INS_STACK_CONSUMPTION: "STACK_CONSUMPTION",
        DefaultClaIns.DEFAULT_APDU_INS_APPLICATION_EXIT: "APPLICATION_EXIT",
        DefaultClaIns.DEFAULT_APDU_INS_APPLICATION_OPEN: "APPLICATION_OPEN",
    }

    return instruction_map.get((cla, ins), "UNKNOWN_INSTRUCTION")


class DefaultAPDUsFactory(Factory):

    def is_recognized(self, data: bytes, hint_chaining: bool) -> Tuple[bool, bool]:
        cla = data[0]
        ins = data[1]
        if not is_valid_default_ins(cla, ins):
            return (False, False)
        else:
            return (True, False)

    def translate_command(self, data: bytes) -> Command:
        cla = data[0]
        ins = data[1]
        if (cla, ins) == DefaultClaIns.DEFAULT_APDU_INS_GET_VERSION:
            return GetVersionCommand(data)
        if (cla, ins) == DefaultClaIns.DEFAULT_APDU_INS_APPLICATION_EXIT:
            return ExitApplicationCommand(data)
        if (cla, ins) == DefaultClaIns.DEFAULT_APDU_INS_APPLICATION_OPEN:
            return OpenApplicationCommand(data)
        else:
            raise NotImplementedError


class DefaultAPDUsCommand(Command):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.ins_str = f"CLA: 0x{self.cla:02x}, INS: 0x{self.ins:02x} ({default_ins_to_text(self.cla, self.ins)})"
        self.header = f"DEFAULT APDU | {self.ins_str}"

    @property
    def next(self):
        return DefaultAPDUsResponse

    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary(self.header),
            summary(self.summary),
        ])


class DefaultAPDUsResponse(Response):
    def __init__(self, data: bytes):
        super().__init__(data)

    def __str__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR ({hex(self.code)} - UNKNOWN')"
        return "\n".join([
            super().__str__(),
            summary(self.summary),
            result
        ])


class GetVersionCommand(DefaultAPDUsCommand):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.summary = "Request application name and version"

    @property
    def next(self):
        return GetVersionResponse


class GetVersionResponse(DefaultAPDUsResponse):
    def __init__(self, data):
        super().__init__(data)
        self.summary = "Name and version of the currently started application"
        self.format, remaining_apdu = l_digest(data)
        self.name_length, self.name, remaining_apdu = lv_digest(remaining_apdu)
        self.version_length, self.version, remaining_apdu = lv_digest(remaining_apdu)
        self.flags_length, self.flags, _ = lv_digest(remaining_apdu)

    def __str__(self):
        return "\n".join([
            super().__str__(),
            item_str(1, "Format", self.format),
            item_str(1, "Name length", self.name_length),
            item_str(1, "Name", f"'{self.name.decode()}'"),
            item_str(1, "Version length", self.version_length),
            item_str(1, "Version", f"'{self.version.decode()}'"),
            item_str(1, "flags length", self.flags_length),
            item_str(1, "flags", self.flags),
        ])


class ExitApplicationCommand(DefaultAPDUsCommand):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.summary = "Request application exit"

    @property
    def next(self):
        return ExitApplicationResponse

    def __str__(self):
        return "\n".join([
            super().__str__(),
        ])


class ExitApplicationResponse(DefaultAPDUsResponse):
    def __init__(self, data):
        super().__init__(data)
        self.summary = "Application acknowledges the request to exit"

    def __str__(self):
        return "\n".join([
            super().__str__(),
        ])


class OpenApplicationCommand(DefaultAPDUsCommand):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.summary = "Request application opening from Dashboard"
        self.name_length = data[4]
        self.name = data[4:]

    @property
    def next(self):
        return OpenApplicationResponse

    def __str__(self):
        return "\n".join([
            super().__str__(),
            item_str(1, "Name length", self.name_length),
            item_str(1, "Name", f"'{self.name.decode()}'"),
        ])


class OpenApplicationResponse(DefaultAPDUsResponse):
    def __init__(self, data):
        super().__init__(data)
        self.summary = "Dashboard acknowledges the request to open the application"

    def __str__(self):
        return "\n".join([
            super().__str__(),
        ])
