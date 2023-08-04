from enum import IntEnum
from base64 import b64decode, urlsafe_b64decode
from typing import Union, Any, Tuple
from ecdsa import curves

from dale.base import Command, Response, Factory

from .pb.exchange_pb2 import NewTransactionResponse, NewSellResponse, NewFundResponse

from . import signature_tester as signature_tester

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

def valid_ins(ins: int) -> bool:
    try:
        Ins(ins)
    except ValueError:
        return False
    return True

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

SUBCOMMAND_TO_TEXT = {
    SubCommand.SWAP: 'SWAP',
    SubCommand.SELL: 'SELL',
    SubCommand.FUND: 'FUND'
}

SUBCOMMAND_TO_CURVE = {
    SubCommand.SWAP: curves.SECP256k1,
    SubCommand.SELL: curves.NIST256p, # == SECP256r1
    SubCommand.FUND: curves.NIST256p, # == SECP256r1
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



INDENT="    "

def summary(summary: str):
    return f"{summary}"

def title(title: str):
    return f"{INDENT}{title}"

def subtitle(s_title: str):
    return f"{INDENT}{INDENT}{s_title}"

def item_str(name: str, field: Any):
    return f"{INDENT}{name}: {str(field)}"

def subitem_str(name: str, field: Any):
    return f"{INDENT}{INDENT}{name}: {str(field)}"

def subsubitem_str(name: str, field: Any):
    return f"{INDENT}{INDENT}{INDENT}{name}: {str(field)}"

def lv_digest(data: bytes) -> Tuple[int, bytes, bytes]:
    if len(data) == 0:
        return (0, b'', b'')
    size = data[0]
    return (size, data[1:1+size], data[1+size:])

def l_digest(data: bytes) -> Tuple[int, bytes]:
    return (data[0], data[1:])

class ExchangeMemory:
    partner_full_credentials: str = None
    partner_public_key: str = None
    transaction: str = None

    def reset(self):
        partner_full_credentials = None
        partner_public_key = None
        transaction = None


class ExchangeFactory(Factory):
    memory = ExchangeMemory()

    def is_recognized(self, data: bytes, last_one_recognized: bool) -> bool:
        if data[0] != EXCHANGE_CLA:
            return False
        if len(data) <= 1:
            return False

        ins = data[1]
        if not valid_ins(ins):
            return False
        elif ins == Ins.GET_VERSION_COMMAND or ins == Ins.START_NEW_TRANSACTION_COMMAND:
            return True
        else:
            # Don't match not entry-point INS that come out of nowhere, they are probably not for us
            return last_one_recognized

    def translate_command(self, data: bytes) -> Command:
        assert data[0] == EXCHANGE_CLA
        assert len(data) > 1
        ins = data[1]
        if ins == Ins.GET_VERSION_COMMAND:
            return GetVersionCommand(data, self.memory)
        if ins == Ins.START_NEW_TRANSACTION_COMMAND:
            return StartNewTransactionCommand(data, self.memory)
        elif ins == Ins.SET_PARTNER_KEY_COMMAND:
            return SetPartnerKeyCommand(data, self.memory)
        elif ins == Ins.CHECK_PARTNER_COMMAND:
            return CheckPartnerCommand(data, self.memory)
        elif ins == Ins.PROCESS_TRANSACTION_RESPONSE_COMMAND:
            return ProcessTransactionCommand(data, self.memory)
        elif ins == Ins.CHECK_TRANSACTION_SIGNATURE_COMMAND:
            return CheckTransactionSignatureCommand(data, self.memory)
        elif ins == Ins.CHECK_PAYOUT_ADDRESS:
            return CheckPayoutAddress(data, self.memory)
        elif ins == Ins.CHECK_REFUND_ADDRESS:
            return CheckRefundAddress(data, self.memory)
        elif ins == Ins.START_SIGNING_TRANSACTION:
            return StartSigningTransaction(data, self.memory)
        else:
            return ExchangeCommand(data)


class ExchangeResponse(Response):
    def __str__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR {ERRORS.get(self.code, 'UNKNOWN')} ({hex(self.code)} - '{ERRORS[self.code]}')"
        return "\n".join([
            super().__str__(),
            result
        ])


class ExchangeCommand(Command):
    def __init__(self, data, memory = None):
        assert data[0] == EXCHANGE_CLA, \
            f"This question with CLA '{hex(data[0])}' is not for the Exchange application"
        super().__init__(data)
        assert self.ins in INS
        assert self.rate in RATE
        assert self.subcommand in SUBCOMMAND_TO_TEXT
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
            super().__str__(),
            f"{INS[self.ins]} - {RATE[self.rate]} - {SUBCOMMAND_TO_TEXT[self.subcommand]}"
        ])


class GetVersionResponse(ExchangeResponse):
    def __init__(self, data):
        super().__init__(data)
        # TODO: real fix by having the GetVersionCommand refuse to recognize
        # assert len(self.data) == 3
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
    def __init__(self, data, memory):
        super().__init__(data)
        memory.reset()
    @property
    def next(self):
        return StartNewTransactionResponse
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Starting a new transaction"),
        ])


class SetPartnerKeyCommand(ExchangeCommand):
    def __init__(self, data, memory):
        super().__init__(data)
        self.name_length = self.data[0]
        self.name = self.data[1:self.name_length+1]
        self.public_key = self.data[self.name_length+1:]

        memory.partner_full_credentials = self.data
        memory.partner_public_key = self.public_key

    @property
    def partner_key(self):
        return self.data
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Partner credentials"),
            "",
            item_str("Partner name length", self.name_length),
            item_str("Partner name", self.name),
            item_str("Partner public_key", self.public_key.hex())
        ])


class CheckPartnerCommand(ExchangeCommand):
    def __init__(self, data, memory):
        super().__init__(data)
        if signature_tester.check_ledger_prod_signature(memory.partner_full_credentials, self.data):
            self.sign_check_text = "    (Valid signature of the partner credentials by the Ledger PROD key)"
        elif signature_tester.check_ledger_test_signature(memory.partner_full_credentials, self.data):
            self.sign_check_text = "    (Valid signature of the partner credentials by the Ledger TEST key)"
        else:
            self.sign_check_text = "    (/!\\ This is NOT a valid signature of the partner credentials by any of the Ledger keys)"

    @property
    def partner_signature(self):
        return self.data
    def __str__(self) -> str:
        return "\n".join([
            super().__str__(),
            summary("Partner credentials signed by the Ledger key"),
            "",
            item_str("Signature", self.data.hex()),
            self.sign_check_text,
        ])


class ProcessTransactionCommand(ExchangeCommand):
    def __init__(self, data, memory):
        super().__init__(data)
        assert len(self.data) >= 1 + self.payload_length
        assert len(self.data) == 1 + self.payload_length + 1 + self.fees_length
        self._raw_payload = self.data[1:1+self.payload_length]
        if self.subcommand == SubCommand.SWAP:
            decoded = self._raw_payload
            self._payload = NewTransactionResponse.FromString(decoded)
        else:
            decoded = urlsafe_b64decode(self._raw_payload)
            if self.subcommand == SubCommand.SELL:
                self._payload = NewSellResponse.FromString(decoded)
            else:  # SubCommand.FUND
                self._payload = NewFundResponse.FromString(decoded)
        memory.transaction = self._raw_payload

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
            "",
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
    def __init__(self, data, memory):
        super().__init__(data)
        self._signature = self.data
        if signature_tester.check_partner_signature(memory.partner_public_key, memory.transaction, self.data, SUBCOMMAND_TO_CURVE[self.subcommand]):
            self.sign_check_text = "    (Valid signature of the transaction by the partner key)"
        else:
            self.sign_check_text = "    (/!\\ This is NOT a valid signature of the transaction by the partner key)"

    @property
    def signature(self) -> str:
        return self._signature
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Signature by the partner of the proposed transaction"),
            "",
            item_str("Signature", self.signature.hex()),
            self.sign_check_text,
        ])


class CheckAddress(ExchangeCommand):
    summary = None
    def __init__(self, data, memory):
        super().__init__(data)
        # gathering configuration
        assert len(self.data) >= 1

        self.configuration_length, self._configuration, remaining_apdu = lv_digest(self.data)

        self.ticker_length, self.ticker, remaining_conf = lv_digest(self._configuration)
        self.appname_length, self.appname, remaining_conf = lv_digest(remaining_conf)
        self.subconfiguration_length, subconfig, remaining_conf = lv_digest(remaining_conf)
        assert remaining_conf == b''  # ?
        if self.subconfiguration_length > 0:
            self.subticker_length, self.subticker, remaining_subconf = lv_digest(subconfig)
            self.coefficient, remaining_subconf = l_digest(remaining_subconf)
            assert remaining_subconf == b''  # ?

        self.signature_header, remaining_apdu = l_digest(remaining_apdu)
        self.signature_length, self._signature, remaining_apdu = lv_digest(remaining_apdu)

        self.derivation_path_length, self._derivation_path, remaining_apdu = lv_digest(remaining_apdu)

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
            summary(self.summary),
            "",
            item_str("Coin configuration length", self.configuration_length),
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
            "",
            item_str("Coin configuration signature header", self.signature_header),
            item_str("Coin configuration signature length", self.signature_length),
            item_str("Coin configuration signature", self.signature.hex()),
            "",
            item_str("Derivation path length", self.derivation_path_length),
            item_str("Derivation path", self.derivation_path.hex()),
        ])
        return string


class CheckPayoutAddress(CheckAddress):
    summary = "Configuration for TO currency"


class CheckRefundAddress(CheckAddress):
    summary = "Configuration for FROM currency"


class StartSigningTransaction(ExchangeCommand):
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Request the start of the paying coin application"),
        ])
