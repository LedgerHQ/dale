from enum import IntEnum
from base64 import b64decode
from typing import Union

from dale.base import Command, Response

from .pb.exchange_pb2 import NewTransactionResponse, NewSellResponse, NewFundResponse


EXCHANGE_CLA = 0xE0

class Ins(IntEnum):
    GET_VERSION_COMMAND                  = 0x02
    START_NEW_TRANSACTION_COMMAND        = 0x03
    SET_PARTNER_KEY_COMMAND              = 0x04
    CHECK_PARTNER_COMMAND                = 0x05
    PROCESS_TRANSACTION_RESPONSE_COMMAND = 0x06
    CHECK_TRANSACTION_SIGNATURE_COMMAND  = 0x07
    CHECK_PAYOUT_ADDRESS                 = 0x08
    CHECK_REFUND_ADDRESS                 = 0x09
    START_SIGNING_TRANSACTION            = 0x0A


INS = {
    Ins.GET_VERSION_COMMAND:                  'GET_VERSION_COMMAND',
    Ins.START_NEW_TRANSACTION_COMMAND:        'START_NEW_TRANSACTION_COMMAND',
    Ins.SET_PARTNER_KEY_COMMAND:              'SET_PARTNER_KEY_COMMAND',
    Ins.CHECK_PARTNER_COMMAND:                'CHECK_PARTNER_COMMAND',
    Ins.PROCESS_TRANSACTION_RESPONSE_COMMAND: 'PROCESS_TRANSACTION_RESPONSE_COMMAND',
    Ins.CHECK_TRANSACTION_SIGNATURE_COMMAND:  'CHECK_TRANSACTION_SIGNATURE_COMMAND',
    Ins.CHECK_PAYOUT_ADDRESS:                 'CHECK_PAYOUT_ADDRESS',
    Ins.CHECK_REFUND_ADDRESS:                 'CHECK_REFUND_ADDRESS',
    Ins.START_SIGNING_TRANSACTION:            'START_SIGNING_TRANSACTION'
}

class Rate(IntEnum):
    FIXED    = 0x00
    FLOATING = 0x01

RATE = {
    Rate.FIXED:    'FIXED',
    Rate.FLOATING: 'FLOATING'
}


class SubCommand(IntEnum):
    SWAP = 0x00
    SELL = 0x01
    FUND = 0x02

SUBCOMMAND = {
    SubCommand.SWAP: 'SWAP',
    SubCommand.SELL: 'SELL',
    SubCommand.FUND: 'FUND'
}


ERRORS = {
    0x6A80: "INCORRECT_COMMAND_DATA",
    0x6A81: "DESERIALIZATION_FAILED",
    0x6A82: "WRONG_TRANSACTION_ID",
    0x6A83: "INVALID_ADDRESS",
    0x6A84: "USER_REFUSED",
    0x6A85: "INTERNAL_ERROR",
    0x6A86: "WRONG_P1",
    0x6A87: "WRONG_P2",
    0x6E00: "CLASS_NOT_SUPPORTED",
    0x6D00: "INVALID_INSTRUCTION",
    0x9D1A: "SIGN_VERIFICATION_FAIL"
}


def raw_hex_str(name: str, field: bytes):
    return f"{name}:\n\t{field!r}\n\t{field.hex()}"


def factory(data):
    assert data[0] == EXCHANGE_CLA
    assert len(data) > 1
    ins = data[1]
    if ins == Ins.GET_VERSION_COMMAND:
        return GetVersionCommand(data)
    if ins == Ins.START_NEW_TRANSACTION_COMMAND:
        return StartNewTransactionCommand(data)
    elif ins == Ins.SET_PARTNER_KEY_COMMAND:
        return SetPartnerKeyCommand(data)
    elif ins == Ins.CHECK_PARTNER_COMMAND:
        return CheckPartnerCommand(data)
    elif ins == Ins.PROCESS_TRANSACTION_RESPONSE_COMMAND:
        return ProcessTransactionCommand(data)
    else:
        return ExchangeCommand(data)


class ExchangeResponse(Response):
    def __str__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR {ERRORS.get(self.code, 'UNKNOWN')} (0x{hex(self.code)})"
        return "\n< ".join([
            "-"*30,
            result
        ])


class ExchangeCommand(Command):
    def __init__(self, data):
        assert data[0] == EXCHANGE_CLA, \
            f"This question with CLA '{hex(data[0])}' is not for the Exchange application"
        super().__init__(data)
        assert self.ins in INS
        assert self.rate in RATE
        assert self.subcommand in SUBCOMMAND
    @property
    def rate(self):
        return self.p1
    @property
    def subcommand(self):
        return self.p2
    @property
    def next(self):
        return ExchangeResponse
    def __str__(self):
        return "\n".join([
            "="*30,
            f"> {INS[self.ins]} - {RATE[self.rate]} - {SUBCOMMAND[self.subcommand]}",
        ])


class GetVersionResponse(ExchangeResponse):
    def __init__(self, data):
        super().__init__(data)
        assert len(self.data) == 3
    @property
    def major(self) -> int:
        return self.data[0]
    @property
    def minor(self) -> int:
        return self.data[1]
    @property
    def patch(self) -> int:
        return self.data[2]
    def __str__(self):
        return "\n".join([
            super().__str__(),
            f"Version: {self.major}.{self.minor}.{self.patch}"
        ])

class GetVersionCommand(ExchangeCommand):
    @property
    def next(self):
        return GetVersionResponse

class StartNewTransactionResponse(ExchangeResponse):
    @property
    def transaction_id(self):
        return self.data
    def __str__(self):
        return "\n".join([
            super().__str__(),
            raw_hex_str("TRANSACTION_ID", self.transaction_id)
        ])


class StartNewTransactionCommand(ExchangeCommand):
    @property
    def next(self):
        return StartNewTransactionResponse


class SetPartnerKeyCommand(ExchangeCommand):
    @property
    def partner_key(self):
        return self.data
    def __str__(self):
        return "\n".join([
            super().__str__(),
            raw_hex_str("Partner key", self.partner_key)
        ])


class CheckPartnerCommand(ExchangeCommand):
    @property
    def partner_signature(self):
        return self.data
    def __str__(self) -> str:
        return "\n".join([
            super().__str__(),
            raw_hex_str("Partner signature", self.partner_signature)
        ])


class ProcessTransactionCommand(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        if self.subcommand == SubCommand.SWAP:
            assert len(self.data) >= 1 + self.payload_length
            assert len(self.data) == 1 + self.payload_length + 1 + self.fees_length
            self._payload = NewTransactionResponse.FromString(self.data[1:1+self.payload_length])
        else:
            assert len(self.data) == 1 + self.payload_length
            decoded = b64decode(self.data[1:])
            if self.subcommand == SubCommand.SELL:
                self._payload = NewSellResponse(decoded)
            else:  # SubCommand.FUND
                self.payload = NewFundResponse(decoded)
    @property
    def payload_length(self) -> int:
        return self.data[0]
    @property
    def payload(self) -> Union[NewTransactionResponse, NewSellResponse, NewFundResponse]:
        return self._payload
    @property
    def fees_offset(self) -> int:
        return self.payload_length + 2
    @property
    def fees_length(self) -> int:
        return self.data[self.fees_offset - 1]
    @property
    def fees(self) -> bytes:
        return self.data[self.fees_offset:self.fees_offset + self.fees_length]
    def __str__(self) -> str:
        return "\n".join([
            super().__str__(),
            str(self.payload),
            raw_hex_str("Fees", self.fees)
        ])


class CheckTransactionSignatureCommand(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)

    # def __str__(self):
    #     return "\n".join([
    #         super().__str__(),
