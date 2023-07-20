from enum import IntEnum
from base64 import b64decode, urlsafe_b64decode
from typing import Union, Any

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

def summary(summary: str):
    return f"{summary}\n"

def title(title: str):
    return f"    {title}"

def subtitle(s_title: str):
    return f"        {s_title}"

def item_str(name: str, field: Any):
    return f"    {name}: {str(field)}"

def subitem_str(name: str, field: Any):
    return f"        {name}: {str(field)}"

def subsubitem_str(name: str, field: Any):
    return f"            {name}: {str(field)}"

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
    elif ins == Ins.CHECK_TRANSACTION_SIGNATURE_COMMAND:
        return CheckTransactionSignatureCommand(data)
    elif ins == Ins.CHECK_PAYOUT_ADDRESS:
        return CheckPayoutAddress(data)
    elif ins == Ins.CHECK_REFUND_ADDRESS:
        return CheckRefundAddress(data)
    elif ins == Ins.START_SIGNING_TRANSACTION:
        return StartSigningTransaction(data)
    else:
        return ExchangeCommand(data)


class ExchangeResponse(Response):
    def __str__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR {ERRORS.get(self.code, 'UNKNOWN')} ({hex(self.code)} - '{ERRORS[self.code]}')"
        return "\n".join([
            "-"*45,
            super().__str__(),
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
            "="*45,
            super().__str__(),
            f"{INS[self.ins]} - {RATE[self.rate]} - {SUBCOMMAND[self.subcommand]}"
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
            item_str("Transaction ID", self.transaction_id),
        ])


class StartNewTransactionCommand(ExchangeCommand):
    @property
    def next(self):
        return StartNewTransactionResponse
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Starting a new transaction"),
        ])


class SetPartnerKeyCommand(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        self.name_length = self.data[0]
        self.name = self.data[1:self.name_length+1]
        self.name = self.data[1:self.name_length+1]
        self.public_key = self.data[self.name_length+1:]

    @property
    def partner_key(self):
        return self.data
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Partner credentials"),
            item_str("Partner name length", self.name_length),
            item_str("Partner name", self.name),
            item_str("Partner public_key", self.public_key.hex())
        ])


class CheckPartnerCommand(ExchangeCommand):
    @property
    def partner_signature(self):
        return self.data
    def __str__(self) -> str:
        return "\n".join([
            super().__str__(),
            summary("Partner credentials signed by our key"),
            item_str("Signature", self.data.hex()),
        ])


class ProcessTransactionCommand(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        assert len(self.data) >= 1 + self.payload_length
        assert len(self.data) == 1 + self.payload_length + 1 + self.fees_length
        if self.subcommand == SubCommand.SWAP:
            self._raw_payload = self.data[1:1+self.payload_length]
            self._payload = NewTransactionResponse.FromString(self._raw_payload)
        else:
            decoded = urlsafe_b64decode(self.data[1:1+self.payload_length] + b'0')
            print(decoded)
            decoded = bytes.fromhex('0A10477265676F722047696C6368726973741216477265676F722047696C636872697374204261616E781A0345544822071A80A85D2454002A2A307832353366623339636265306465346630626432343039613565643539613731653465663164326263322056D4E96A0F95B05D88A0897CDE4AF8248497BCE2834C8919F7DE731B0F04F754')
            print(decoded)
            if self.subcommand == SubCommand.SELL:
                self._raw_payload = decoded
                self._payload = NewSellResponse.FromString(self._raw_payload)
            else:  # SubCommand.FUND
                self._raw_payload = decoded
                self._payload = NewFundResponse.FromString(self._raw_payload)
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
            summary("Transaction & fees proposed by the partner"),
            item_str("Transaction length", self.payload_length),
            item_str("Transaction raw", self._raw_payload.hex()),
            subtitle("Transaction details:"),
            subitem_str("payin_address", self.payload.payin_address),
            subitem_str("refund_address", self.payload.refund_address),
            subitem_str("payout_address", self.payload.payout_address),
            subitem_str("currency_from", self.payload.currency_from),
            subitem_str("currency_to", self.payload.currency_to),
            subitem_str("amount_to_provider", int.from_bytes(self.payload.amount_to_provider, 'big')),
            subitem_str("amount_to_wallet", int.from_bytes(self.payload.amount_to_wallet, 'big')),
            subitem_str("device_transaction_id", self.payload.device_transaction_id),
            item_str("Fees", int.from_bytes(self.fees, 'big'))
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
            summary("Signature by the partner of the proposed transaction"),
            item_str("Signature", self.signature.hex())
        ])

class CheckPayoutAddress(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        # gathering configuration
        assert len(self.data) >= 1
        size = self.data[0]
        assert len(self.data) >= size + 1

        self._configuration = self.data[1:(size + 1)]
        offset=0
        self.ticker_length = self._configuration[offset]
        offset+=1
        self.ticker = self._configuration[offset:offset + self.ticker_length]
        offset+=self.ticker_length
        self.appname_length = self._configuration[offset]
        offset+=1
        self.appname = self._configuration[offset:offset + self.appname_length]
        offset+=self.appname_length
        self.subconfiguration_length = self._configuration[offset]
        offset+=1
        if self.subconfiguration_length > 0:
            self.subticker_length = self._configuration[offset]
            offset+=1
            self.subticker = self._configuration[offset:offset+self.subticker_length]
            offset+=self.subticker_length
            self.coefficient = self._configuration[offset]

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
            summary("Configuration for TO currency"),
            item_str("Coin configuration", self.configuration.hex()),
            subitem_str("Ticker length", self.ticker_length),
            subitem_str("Ticker", self.ticker.decode()),
            subitem_str("Application name length", self.appname_length),
            subitem_str("Application name", self.appname.decode()),
            subitem_str("Subconfiguration length", self.subconfiguration_length),
            ])
        if self.subconfiguration_length > 0:
            string = "\n".join([
                string,
                subsubitem_str("Subticker length", self.subticker_length),
                subsubitem_str("Subticker", self.subticker.decode()),
                subsubitem_str("Subconfiguration coefficient", self.coefficient),
            ])
        string = "\n".join([
            string,
            item_str("Coin configuration signature", self.signature.hex()),
            item_str("Derivation path", self.derivation_path.hex()),
        ])

class CheckRefundAddress(ExchangeCommand):
    def __init__(self, data):
        super().__init__(data)
        # gathering configuration
        assert len(self.data) >= 1
        size = self.data[0]
        assert len(self.data) >= size + 1
        self._configuration = self.data[1:(size + 1)]
        offset=0
        self.ticker_length = self._configuration[offset]
        offset+=1
        self.ticker = self._configuration[offset:offset + self.ticker_length]
        offset+=self.ticker_length
        self.appname_length = self._configuration[offset]
        offset+=1
        self.appname = self._configuration[offset:offset + self.appname_length]
        offset+=self.appname_length
        self.subconfiguration_length = self._configuration[offset]
        offset+=1
        if self.subconfiguration_length > 0:
            self.subticker_length = self._configuration[offset]
            offset+=1
            self.subticker = self._configuration[offset:offset+self.subticker_length]
            offset+=self.subticker_length
            self.coefficient = self._configuration[offset]

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
        string = "\n".join([
            super().__str__(),
            summary("Configuration for FROM currency"),
            item_str("Coin configuration", self.configuration.hex()),
            subitem_str("Ticker length", self.ticker_length),
            subitem_str("Ticker", self.ticker.decode()),
            subitem_str("Application name length", self.appname_length),
            subitem_str("Application name", self.appname.decode()),
            subitem_str("Subconfiguration length", self.subconfiguration_length),
            ])
        if self.subconfiguration_length > 0:
            string = "\n".join([
                string,
                subsubitem_str("Subticker length", self.subticker_length),
                subsubitem_str("Subticker", self.subticker.decode()),
                subsubitem_str("Subconfiguration coefficient", self.coefficient),
            ])
        string = "\n".join([
            string,
            item_str("Coin configuration signature", self.signature.hex()),
            item_str("Derivation path", self.derivation_path.hex()),
        ])

        return string

class StartSigningTransaction(ExchangeCommand):
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Request the start of the paying coin application"),
        ])
