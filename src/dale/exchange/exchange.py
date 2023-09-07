import struct
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
    CHECK_ASSET_IN                       = 0x0B
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
    Ins.CHECK_ASSET_IN:                       'CHECK_ASSET_IN',
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
    SWAP    = 0x00
    SELL    = 0x01
    FUND    = 0x02
    SWAP_NG = 0x03
    SELL_NG = 0x04
    FUND_NG = 0x05

SUBCOMMAND_MASK = 0x0F

SUBCOMMAND_TO_TEXT = {
    SubCommand.SWAP: 'SWAP',
    SubCommand.SELL: 'SELL',
    SubCommand.FUND: 'FUND',
    SubCommand.SWAP_NG: 'SWAP_NG',
    SubCommand.SELL_NG: 'SELL_NG',
    SubCommand.FUND_NG: 'FUND_NG',
}

SUBCOMMAND_TO_CURVE = {
    SubCommand.SWAP: curves.SECP256k1,
    SubCommand.SELL: curves.NIST256p, # == SECP256r1
    SubCommand.FUND: curves.NIST256p, # == SECP256r1
    SubCommand.SWAP_NG: curves.NIST256p,
    SubCommand.SELL_NG: curves.NIST256p,
    SubCommand.FUND_NG: curves.NIST256p,
}

SUBCOMMAND_TO_SIZE_OF_PAYLOAD_LENGTH_FIELD = {
    SubCommand.SWAP: 1,
    SubCommand.SELL: 1,
    SubCommand.FUND: 1,
    SubCommand.SWAP_NG: 2,
    SubCommand.SELL_NG: 2,
    SubCommand.FUND_NG: 2,
}

class Extension(IntEnum):
    P2_NONE   = (0x00 << 4)
    P2_EXTEND = (0x01 << 4)
    P2_MORE   = (0x02 << 4)

EXTENSION_MASK = 0xF0

EXTENSION_TO_TEXT = {
    Extension.P2_NONE: 'P2_NONE',
    Extension.P2_EXTEND: 'P2_EXTEND',
    Extension.P2_MORE: 'P2_MORE',
    Extension.P2_MORE | Extension.P2_EXTEND: 'P2_MORE & P2_EXTEND',
}


ERRORS = {
    0x6A80: "INCORRECT_COMMAND_DATA",
    0x6A81: "DESERIALIZATION_FAILED",
    0x6A82: "WRONG_TRANSACTION_ID",
    0x6A83: "INVALID_ADDRESS",
    0x6A84: "USER_REFUSED",
    0x6A85: "INTERNAL_ERROR",
    0x6A86: "WRONG_P1",
    0x6A87: "WRONG_P2_SUBCOMMAND",
    0x6A88: "WRONG_P2_EXTENSION",
    0x6A89: "INVALID_P2_EXTENSION",
    0x6E00: "CLASS_NOT_SUPPORTED",
    0x6E01: "MALFORMED_APDU",
    0x6E02: "INVALID_DATA_LENGTH",
    0x6D00: "INVALID_INSTRUCTION",
    0x6D01: "UNEXPECTED_INSTRUCTION",
    0x9D1A: "SIGN_VERIFICATION_FAIL",
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
    reconstructed_data: str = None
    transaction_length: str = None
    transaction: str = None

    def reset(self):
        partner_full_credentials = None
        partner_public_key = None
        reconstructed_data = None
        transaction_length = None
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
        elif ins == Ins.CHECK_ASSET_IN:
            return CheckAssetIn(data, self.memory)
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
        return self.p2 & SUBCOMMAND_MASK

    @property
    def extension(self):
        return self.p2 & EXTENSION_MASK

    @property
    def next(self):
        return ExchangeResponse

    def __str__(self):
        return "\n".join([
            super().__str__(),
            f"{INS[self.ins]} - {RATE[self.rate]} - {SUBCOMMAND_TO_TEXT[self.subcommand]} - {EXTENSION_TO_TEXT[self.extension]}"
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
        if self.extension & Extension.P2_EXTEND:
            memory.reconstructed_data += self.data
        else:
            memory.reconstructed_data = self.data
            if self.size_of_payload_length_field == 1:
                memory.transaction_length = memory.reconstructed_data[0]
            elif self.size_of_payload_length_field == 2:
                memory.transaction_length = struct.unpack(">H", memory.reconstructed_data[0:2])[0]

        self.payload_length = memory.transaction_length
        self.current_raw_reception = memory.reconstructed_data

        if not self.extension & Extension.P2_MORE:
            self.payload = memory.reconstructed_data[self.size_of_payload_length_field:self.size_of_payload_length_field + memory.transaction_length]
            memory.transaction = self.payload
            fees_offset = self.size_of_payload_length_field + memory.transaction_length
            self.fees_length = memory.reconstructed_data[fees_offset]
            self.fees = memory.reconstructed_data[fees_offset + 1:fees_offset + 1 + self.fees_length]

    @property
    def size_of_payload_length_field(self) -> int:
        return SUBCOMMAND_TO_SIZE_OF_PAYLOAD_LENGTH_FIELD[self.subcommand]
    @property
    def decoded_payload(self) -> Union[NewTransactionResponse, NewSellResponse, NewFundResponse]:
        if self.subcommand == SubCommand.SWAP:
            decoded = self.payload
            return NewTransactionResponse.FromString(decoded)
        else:
            decoded = urlsafe_b64decode(self.payload)
            if self.subcommand == SubCommand.SELL or self.subcommand == SubCommand.SELL_NG:
                return NewSellResponse.FromString(decoded)
            elif self.subcommand == SubCommand.FUND or self.subcommand == SubCommand.FUND_NG:
                return NewFundResponse.FromString(decoded)
            else:  # SubCommand.SWAP_NG
                return NewTransactionResponse.FromString(decoded)

    @property
    def summary_str(self) -> str:
        suffix = "Transaction & fees proposed by the partner"
        if self.extension & Extension.P2_EXTEND:
            suffix += ", appending to previously received APDU"
        if self.extension & Extension.P2_MORE:
            suffix += ", expecting more APDU"
        return suffix

    @property
    def decoded_pb(self) -> str:
        if self.subcommand == SubCommand.SWAP or self.subcommand == SubCommand.SWAP_NG:
            ret = "\n".join([
                subitem_str("payin_address", self.decoded_payload.payin_address),
                subitem_str("refund_address", self.decoded_payload.refund_address),
                subitem_str("payout_address", self.decoded_payload.payout_address),
                subitem_str("currency_from", self.decoded_payload.currency_from),
                subitem_str("currency_to", self.decoded_payload.currency_to),
                subitem_str("amount_to_provider", int.from_bytes(self.decoded_payload.amount_to_provider, 'big')),
                subitem_str("amount_to_wallet", int.from_bytes(self.decoded_payload.amount_to_wallet, 'big')),
            ])
            if self.subcommand == SubCommand.SWAP:
                ret += "\n" + subitem_str("device_transaction_id", self.decoded_payload.device_transaction_id)
            else:
                ret += "\n" + subitem_str("device_transaction_id_ng", self.decoded_payload.device_transaction_id_ng)
        elif self.subcommand == SubCommand.SELL or self.subcommand == SubCommand.SELL_NG:
            ret = "\n".join([
                subitem_str("trader_email", self.decoded_payload.trader_email),
                subitem_str("in_currency", self.decoded_payload.in_currency),
                subitem_str("in_amount", self.decoded_payload.in_amount),
                subitem_str("in_address", self.decoded_payload.in_address),
                subitem_str("out_currency", self.decoded_payload.out_currency),
                subitem_str("out_amount", self.decoded_payload.out_amount),
                subitem_str("device_transaction_id", self.decoded_payload.device_transaction_id),
            ])
        elif self.subcommand == SubCommand.FUND or self.subcommand == SubCommand.FUND_NG:
            ret = "\n".join([
                subitem_str("user_id", self.decoded_payload.user_id),
                subitem_str("account_name", self.decoded_payload.account_name),
                subitem_str("in_currency", self.decoded_payload.in_currency),
                subitem_str("in_amount", self.decoded_payload.in_amount),
                subitem_str("in_address", self.decoded_payload.in_address),
                subitem_str("device_transaction_id", self.decoded_payload.device_transaction_id),
            ])
        return ret

    def __str__(self) -> str:
        if self.extension & Extension.P2_MORE:
            return "\n".join([
                super().__str__(),
                summary(self.summary_str),
                "",
                item_str("Total transaction length", self.payload_length),
                item_str("Current transaction raw", self.current_raw_reception.hex()),
            ])
        else:
            return "\n".join([
                super().__str__(),
                summary(self.summary_str),
                "",
                item_str("Transaction length", self.payload_length),
                item_str("Transaction raw", self.current_raw_reception.hex()),
                subtitle("Transaction details:"),
                self.decoded_pb,
                item_str("Fees length", self.fees_length),
                item_str("Fees", int.from_bytes(self.fees, 'big')),
            ])

class CheckTransactionSignatureCommand(ExchangeCommand):
    def __init__(self, data, memory):
        super().__init__(data)
        self._signature = self.data
        message = memory.transaction
        if self.subcommand != SubCommand.SWAP:
            message = b'.' + message
        if signature_tester.check_partner_signature(memory.partner_public_key, message, self.data, SUBCOMMAND_TO_CURVE[self.subcommand]):
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


class CheckAssetIn(CheckAddress):
    summary = "Configuration for TO currency"


class CheckRefundAddress(CheckAddress):
    summary = "Configuration for FROM currency"


class StartSigningTransaction(ExchangeCommand):
    def __str__(self):
        return "\n".join([
            super().__str__(),
            summary("Request the start of the paying coin application"),
        ])
