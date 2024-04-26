from enum import IntEnum
from dale.base import Command, Response, Factory

from ..utils import lv_digest, l_digest
from ..display import summary, item_str

DEFAULT_CLA = 0xB0


class Ins(IntEnum):
    DEFAULT_APDU_INS_GET_VERSION        = 0x01
    DEFAULT_APDU_INS_GET_SEED_COOKIE    = 0x02
    DEFAULT_APDU_INS_STACK_CONSUMPTION  = 0x57
    DEFAULT_APDU_INS_APPLICATION_EXIT   = 0xA7


def valid_ins(ins: int) -> bool:
    try:
        Ins(ins)
    except ValueError:
        return False
    return True


INS = {
    int(Ins.DEFAULT_APDU_INS_GET_VERSION):          'GET_VERSION',
    int(Ins.DEFAULT_APDU_INS_GET_SEED_COOKIE):      'GET_SEED_COOKIE',
    int(Ins.DEFAULT_APDU_INS_STACK_CONSUMPTION):    'STACK_CONSUMPTION',
    int(Ins.DEFAULT_APDU_INS_APPLICATION_EXIT):     'APPLICATION_EXIT',
}


class DefaultAPDUsFactory(Factory):

    def is_recognized(self, data: bytes, last_one_recognized: bool) -> bool:
        if len(data) != 5:
            return False
        if data[0] != DEFAULT_CLA:
            return False

        ins = data[1]
        if not valid_ins(ins):
            return False
        else:
            return True

    def translate_command(self, data: bytes) -> Command:
        ins = data[1]
        if ins == Ins.DEFAULT_APDU_INS_GET_VERSION:
            return GetVersionCommand(data)
        if ins == Ins.DEFAULT_APDU_INS_APPLICATION_EXIT:
            return ExitApplicationCommand(data)
        else:
            raise NotImplementedError


class DefaultAPDUsCommand(Command):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.ins_str = f"Instruction: 0x{self.ins:02x} ({INS[self.ins]})"
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
