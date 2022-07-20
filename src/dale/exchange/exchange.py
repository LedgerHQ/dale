from enum import IntEnum
from base64 import b64decode, urlsafe_b64decode
from typing import Union

from dale.base import Command, Response

from .pb.exchange_pb2 import NewTransactionResponse, NewSellResponse, NewFundResponse

CONFIGURATION_DER_SIGNATURE_LENGTH = 70

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
    elif ins == Ins.CHECK_PAYOUT_ADDRESS:
        return CheckPayoutAddress(data)
    elif ins == Ins.CHECK_REFUND_ADDRESS:
        return CheckRefundAddress(data)
    else:
        return ExchangeCommand(data)


class ExchangeResponse(Response):
    def __str__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR {ERRORS.get(self.code, 'UNKNOWN')} ({hex(self.code)} - '{ERRORS[self.code]}')"
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
        assert len(self.data) >= 1 + self.payload_length
        assert len(self.data) == 1 + self.payload_length + 1 + self.fees_length
        if self.subcommand == SubCommand.SWAP:
            self._payload = NewTransactionResponse.FromString(self.data[1:1+self.payload_length])
        else:
            decoded = urlsafe_b64decode(self.data[1:1+self.payload_length] + b'0')
            print(decoded)
            decoded = bytes.fromhex('0A10477265676F722047696C6368726973741216477265676F722047696C636872697374204261616E781A0345544822071A80A85D2454002A2A307832353366623339636265306465346630626432343039613565643539613731653465663164326263322056D4E96A0F95B05D88A0897CDE4AF8248497BCE2834C8919F7DE731B0F04F754')
            print(decoded)
            if self.subcommand == SubCommand.SELL:
                self._payload = NewSellResponse.FromString(decoded)
            else:  # SubCommand.FUND
                self._payload = NewFundResponse.FromString(decoded)
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
        self._signature = self.data
    @property
    def signature(self) -> str:
        return self._signature
    def __str__(self):
        return "\n".join([
            super().__str__(),
            raw_hex_str("Signature", self.signature)
        ])

class CheckPayoutAddress(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        # gathering configuration
        assert len(self.data) >= 1
        size = self.data[0]
        assert len(self.data) >= size + 1
        self._configuration = self.data[1:(size + 1)]
        self.data = self.data[(size + 1):]
        # gathering DER signature
        assert len(self.data) >= CONFIGURATION_DER_SIGNATURE_LENGTH
        assert self.data[0] == 0x30
        size = self.data[1]
        self._signature = self.data[:2+size]
        self.data = self.data[2+size:]
        # gathering derivation path
        assert len(self.data) >= 1
        size = self.data[0]
        assert len(self.data) == 1 + size
        self._derivation_path = self.data[1:size]
    @property
    def configuration(self) -> str:
        return self._configuration
    @property
    def signature(self) -> str:
        return self._signature
    @property
    def derivation_path(self) -> str:
        return self._derivation_path
    def __str__(self):
        return "\n".join([
            super().__str__(),
            raw_hex_str("Configuration", self.configuration),
            raw_hex_str("Signature", self.signature),
            raw_hex_str("Derivation path", self.derivation_path),
        ])

class CheckRefundAddress(ExchangeCommand):
    pass
