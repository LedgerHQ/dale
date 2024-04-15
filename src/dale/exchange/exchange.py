import struct
from enum import IntEnum
from base64 import urlsafe_b64decode
from typing import Any, Tuple, Optional, List
from ecdsa import curves
from ecdsa.curves import Curve
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from dale.base import Command, Response, Factory

from .pb import NewTransactionResponse, NewSellResponse, NewFundResponse

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
    int(Ins.GET_VERSION_COMMAND):                  'GET_VERSION',
    int(Ins.START_NEW_TRANSACTION_COMMAND):        'START_NEW_TRANSACTION',
    int(Ins.SET_PARTNER_KEY_COMMAND):              'SET_PARTNER_KEY',
    int(Ins.CHECK_PARTNER_COMMAND):                'CHECK_PARTNER',
    int(Ins.PROCESS_TRANSACTION_RESPONSE_COMMAND): 'PROCESS_TRANSACTION_RESPONSE',
    int(Ins.CHECK_TRANSACTION_SIGNATURE_COMMAND):  'CHECK_TRANSACTION_SIGNATURE',
    int(Ins.CHECK_PAYOUT_ADDRESS):                 'CHECK_PAYOUT_ADDRESS',
    int(Ins.CHECK_ASSET_IN):                       'CHECK_ASSET_IN',
    int(Ins.CHECK_REFUND_ADDRESS):                 'CHECK_REFUND_ADDRESS',
    int(Ins.START_SIGNING_TRANSACTION):            'START_SIGNING_TRANSACTION'
}


class Rate(IntEnum):
    FIXED = 0x00
    FLOATING = 0x01


RATE = {
    int(Rate.FIXED): 'FIXED',
    int(Rate.FLOATING): 'FLOATING'
}


class SubCommand(IntEnum):
    SWAP = 0x00
    SELL = 0x01
    FUND = 0x02
    SWAP_NG = 0x03
    SELL_NG = 0x04
    FUND_NG = 0x05


SUBCOMMAND_MASK = 0x0F

SUBCOMMAND_TO_TEXT = {
    int(SubCommand.SWAP): 'SWAP',
    int(SubCommand.SELL): 'SELL',
    int(SubCommand.FUND): 'FUND',
    int(SubCommand.SWAP_NG): 'SWAP_NG',
    int(SubCommand.SELL_NG): 'SELL_NG',
    int(SubCommand.FUND_NG): 'FUND_NG',
}


class Extension(IntEnum):
    P2_NONE = (0x00 << 4)
    P2_EXTEND = (0x01 << 4)
    P2_MORE = (0x02 << 4)


EXTENSION_MASK = 0xF0

EXTENSION_TO_TEXT = {
    int(Extension.P2_NONE): 'P2_NONE',
    int(Extension.P2_EXTEND): 'P2_EXTEND',
    int(Extension.P2_MORE): 'P2_MORE',
    int(Extension.P2_MORE | Extension.P2_EXTEND): 'P2_MORE & P2_EXTEND',
}


class CurveId(IntEnum):
    SECP256K1 = 0x00
    SECP256R1 = 0x01


class PayloadEncoding(IntEnum):
    BYTES_ARRAY = 0x00
    BASE_64_URL = 0x01


class SignatureComputation(IntEnum):
    BINARY_ENCODED_PAYLOAD = 0x00
    DOT_PREFIXED_BASE_64_URL = 0x01


class SignatureEncoding(IntEnum):
    DER = 0x00
    PLAIN_R_S = 0x01


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

INDENT = "    "


def summary(summary: str):
    return f"{summary}"


def title(level: int, title: str):
    return f"{INDENT * level}{title}"


def item_str(level: int, name: str, field: Any):
    return f"{INDENT * level}{name}: {str(field)}"


def lv_digest(data: bytes) -> Tuple[int, bytes, bytes]:
    if len(data) == 0:
        return (0, b'', b'')
    size = data[0]
    return (size, data[1:1 + size], data[1 + size:])


def l_digest(data: bytes) -> Tuple[int, bytes]:
    return (data[0], data[1:])


def bytes_to_raw_str(b: bytes) -> str:
    return ''.join('{:02x}'.format(x) for x in b)


class ExchangeMemory:
    partner_full_credentials: Optional[bytes] = None
    partner_key: Optional[bytes] = None
    partner_curve: Optional[Curve] = None
    reconstructed_data: Optional[bytes] = None
    transaction: Optional[bytes] = None

    def reset(self):
        self.partner_full_credentials = None
        self.partner_key = None
        self.partner_curve = None
        self.reconstructed_data = None
        self.transaction = None


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
            return (data[4] == 0x00)
        else:
            # Don't match not entry-point INS that come out of nowhere, they are probably not for us
            return last_one_recognized

    def translate_command(self, data: bytes) -> Command:
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
            result = f"ERROR ({hex(self.code)} - '{ERRORS.get(self.code, 'UNKNOWN')}')"
        return "\n".join([
            super().__str__(),
            result
        ])


class ExchangeCommand(Command):
    def __init__(self, data: bytes, memory: Optional[ExchangeMemory] = None):
        super().__init__(data)
        self.error = False
        if self.ins in INS:
            self.ins_str = f"Instruction: 0x{self.ins:02x} ({INS[self.ins]})"
        else:
            self.ins_str = f"Instruction: 0x{self.ins:02x} (UNRECOGNIZED)"
        if self.rate in RATE:
            self.rate_str = f"Rate: 0x{self.rate:02x} ({RATE[self.rate]})"
        else:
            self.rate_str = f"Rate: 0x{self.rate:02x} (UNRECOGNIZED)"
        if self.subcommand in SUBCOMMAND_TO_TEXT:
            self.subcommand_str = f"Flow: 0x{self.subcommand:02x} ({SUBCOMMAND_TO_TEXT[self.subcommand]})"
        else:
            self.subcommand_str = f"Flow: 0x{self.subcommand:02x} (UNRECOGNIZED)"
        if self.extension in EXTENSION_TO_TEXT:
            self.extension_str = f"Extension: 0x{self.extension:02x} ({EXTENSION_TO_TEXT[self.extension]})"
        else:
            self.extension_str = f"Extension: 0x{self.extension:02x} (UNRECOGNIZED)"

    @property
    def rate(self):
        return self.p1

    @property
    def subcommand(self):
        return self.p2 & SUBCOMMAND_MASK

    @property
    def is_ng(self):
        return (self.subcommand in [SubCommand.SWAP_NG, SubCommand.SELL_NG, SubCommand.FUND_NG])

    @property
    def is_legacy(self):
        return not self.is_ng

    @property
    def is_swap(self):
        return (self.subcommand in [SubCommand.SWAP, SubCommand.SWAP_NG])

    @property
    def is_sell(self):
        return (self.subcommand in [SubCommand.SELL, SubCommand.SELL_NG])

    @property
    def is_fund(self):
        return (self.subcommand in [SubCommand.FUND, SubCommand.FUND_NG])

    @property
    def extension(self):
        return self.p2 & EXTENSION_MASK

    @property
    def next(self):
        return ExchangeResponse

    def __str__(self):
        return "\n".join([
            super().__str__(),
            f"{self.ins_str} - {self.rate_str} - {self.subcommand_str} - {self.extension_str}"
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
    def transaction_id(self) -> str:
        return bytes_to_raw_str(self.data) if len(self.data) == 32 else str(self.data)

    def __str__(self):
        return "\n".join([
            super().__str__(),
            item_str(1, "Transaction ID", self.transaction_id),
        ])


class StartNewTransactionCommand(ExchangeCommand):
    def __init__(self, data: bytes, memory: ExchangeMemory):
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
    def __init__(self, data: bytes, memory: ExchangeMemory):
        super().__init__(data)
        self.name_length = self.data[0]
        self.name = self.data[1:1 + self.name_length]
        if self.is_ng:
            self.curve_int = self.data[1 + self.name_length]
            if self.curve_int == CurveId.SECP256K1:
                self.partner_curve = curves.SECP256k1
                self.curve_str = f"0x{self.curve_int:02x} (SECP256K1)"
            elif self.curve_int == CurveId.SECP256R1:
                self.partner_curve = curves.NIST256p
                self.curve_str = f"0x{self.curve_int:02x} (SECP256R1)"
            else:
                self.partner_curve = None
                self.curve_str = f"0x{self.curve_int:02x} (UNRECOGNIZED)"
            pkey_offset = 1 + self.name_length + 1
        else:
            if self.is_swap:
                self.partner_curve = curves.SECP256k1
            else:
                self.partner_curve = curves.NIST256p
            pkey_offset = 1 + self.name_length

        self.public_key = self.data[pkey_offset:]

        memory.partner_full_credentials = self.data
        memory.partner_curve = self.partner_curve
        memory.partner_key = self.public_key

    def __str__(self):
        strings = [
            super().__str__(),
            summary("Partner credentials"),
            "",
            item_str(1, "Partner name length", self.name_length),
            item_str(1, "Partner name", self.name),
        ]
        if self.is_ng:
            strings.append(item_str(1, "Partner curve", self.curve_str))
        strings.append(item_str(1, "Partner public_key", self.public_key.hex()))
        return "\n".join(strings)


class CheckPartnerCommand(ExchangeCommand):
    def __init__(self, data: bytes, memory: ExchangeMemory):
        super().__init__(data)
        if signature_tester.check_ledger_prod_signature(memory.partner_full_credentials, self.data):
            self.sign_check_text = title(1, "(Valid signature of the partner credentials by the Ledger PROD key)")
        elif signature_tester.check_ledger_test_signature(memory.partner_full_credentials, self.data):
            self.sign_check_text = title(1, "(Valid signature of the partner credentials by the Ledger TEST key)")
        else:
            self.sign_check_text = title(1, "(/!\\ This is NOT a valid signature of the partner credentials)")

    @property
    def partner_signature(self):
        return self.data

    def __str__(self) -> str:
        strings = [
            super().__str__(),
            summary("Partner credentials signed by the Ledger key"),
            "",
            item_str(1, "Signature", self.data.hex()),
            self.sign_check_text,
        ]
        return "\n".join(strings)


class ProcessTransactionCommand(ExchangeCommand):
    def __init__(self, data: bytes, memory: ExchangeMemory):
        super().__init__(data)
        if self.extension & Extension.P2_EXTEND and memory.reconstructed_data is not None:
            memory.reconstructed_data += self.data
        else:
            memory.reconstructed_data = self.data
        self.current_raw_reception = memory.reconstructed_data

        if not self.extension & Extension.P2_MORE:
            # Finished receiving, let's parse
            if self.is_legacy:
                self.tx_len = memory.reconstructed_data[0]
                if self.is_swap:
                    self.format_int = int(PayloadEncoding.BYTES_ARRAY)
                else:
                    self.format_int = int(PayloadEncoding.BASE_64_URL)
                tx_offset = 1
            else:
                self.format_int = memory.reconstructed_data[0]
                if self.format_int == int(PayloadEncoding.BYTES_ARRAY):
                    self.format_str = f"0x{self.format_int:02x} (BYTES_ARRAY)"
                elif self.format_int == int(PayloadEncoding.BASE_64_URL):
                    self.format_str = f"0x{self.format_int:02x} (BASE_64_URL)"
                else:
                    self.format_str = f"0x{self.format_int:02x} (UNRECOGNIZED)"
                self.tx_len = struct.unpack(">H", memory.reconstructed_data[1:3])[0]
                tx_offset = 1 + 2

            self.payload = memory.reconstructed_data[tx_offset:tx_offset + self.tx_len]
            memory.transaction = self.payload
            fees_offset = tx_offset + self.tx_len
            self.fees_length = memory.reconstructed_data[fees_offset]
            self.fees = memory.reconstructed_data[fees_offset + 1:fees_offset + 1 + self.fees_length]
            self.decode_pb()

    @property
    def size_of_payload_length_field(self) -> int:
        return (2 if self.is_ng else 1)

    def decode_pb(self):
        self.urlsafe_decoded = None
        self.decoded_payload = None
        # Global try catch in case urlsafe_b64decode or PB throws
        try:
            if self.format_int == int(PayloadEncoding.BYTES_ARRAY):
                self.urlsafe_decoded = self.payload
                self.decoded_payload = NewTransactionResponse.FromString(self.urlsafe_decoded)
            elif self.format_int == int(PayloadEncoding.BASE_64_URL):
                # Add sufficient padding to decode
                self.urlsafe_decoded = urlsafe_b64decode(self.payload + b'==')
                if self.is_swap:
                    self.decoded_payload = NewTransactionResponse.FromString(self.urlsafe_decoded)
                elif self.is_sell:
                    self.decoded_payload = NewSellResponse.FromString(self.urlsafe_decoded)
                elif self.is_fund:
                    self.decoded_payload = NewFundResponse.FromString(self.urlsafe_decoded)
        except Exception:
            pass

    @property
    def summary_str(self) -> str:
        suffix = "Transaction & fees proposed by the partner"
        if self.extension & Extension.P2_EXTEND:
            suffix += ", appending to previously received APDU"
        if self.extension & Extension.P2_MORE:
            suffix += ", expecting more APDU"
        return suffix

    @property
    def decoded_pb(self) -> List[str]:
        if self.decoded_payload is not None:
            if self.is_swap:
                ret = [
                    item_str(2, "payin_address", self.decoded_payload.payin_address),
                    item_str(2, "refund_address", self.decoded_payload.refund_address),
                    item_str(2, "payout_address", self.decoded_payload.payout_address),
                    item_str(2, "currency_from", self.decoded_payload.currency_from),
                    item_str(2, "currency_to", self.decoded_payload.currency_to),
                    item_str(2, "amount_to_provider", int.from_bytes(self.decoded_payload.amount_to_provider, 'big')),
                    item_str(2, "amount_to_wallet", int.from_bytes(self.decoded_payload.amount_to_wallet, 'big')),
                ]
                if self.is_legacy:
                    ret += [item_str(2, "device_transaction_id", self.decoded_payload.device_transaction_id)]
                else:
                    ret += [item_str(2, "device_transaction_id_ng",
                                        bytes_to_raw_str(self.decoded_payload.device_transaction_id_ng))]
            elif self.is_sell:
                ret = [
                    item_str(2, "trader_email", self.decoded_payload.trader_email),
                    item_str(2, "in_currency", self.decoded_payload.in_currency),
                    item_str(2, "in_amount", int.from_bytes(self.decoded_payload.in_amount, 'big')),
                    item_str(2, "in_address", self.decoded_payload.in_address),
                    item_str(2, "out_currency", self.decoded_payload.out_currency),
                    item_str(2, "out_amount", self.decoded_payload.out_amount),
                    item_str(2, "device_transaction_id", bytes_to_raw_str(self.decoded_payload.device_transaction_id)),
                ]
            elif self.is_fund:
                ret = [
                    item_str(2, "user_id", self.decoded_payload.user_id),
                    item_str(2, "account_name", self.decoded_payload.account_name),
                    item_str(2, "in_currency", self.decoded_payload.in_currency),
                    item_str(2, "in_amount", int.from_bytes(self.decoded_payload.in_amount, 'big')),
                    item_str(2, "in_address", self.decoded_payload.in_address),
                    item_str(2, "device_transaction_id", bytes_to_raw_str(self.decoded_payload.device_transaction_id)),
                ]
        else:
            ret = [
                title(3, "FAILED to decode payload"),
            ]
        return ret

    def __str__(self) -> str:
        if self.extension & Extension.P2_MORE:
            strings = [
                super().__str__(),
                summary(self.summary_str),
                "",
                item_str(1, "Current transaction raw", self.current_raw_reception.hex()),
            ]
            return "\n".join(strings)
        else:
            # Header
            strings = [
                super().__str__(),
                summary(self.summary_str),
                "",
            ]

            # Format on NG apdus
            if self.is_ng:
                strings.append(item_str(1, "Transaction encoding", self.format_str))

            # Raw TX
            strings += [
                item_str(1, "Transaction length", self.tx_len),
                item_str(1, "Transaction raw", self.payload.hex()),
                item_str(1, "Urlsafe b64 decoded", self.urlsafe_decoded.hex()),
                title(2, "Transaction details:"),
            ]

            # PB content
            strings += self.decoded_pb
            # Fees
            strings += [
                item_str(1, "Fees length", self.fees_length),
                item_str(1, "Fees", int.from_bytes(self.fees, 'big')),
            ]
            return "\n".join(strings)


class CheckTransactionSignatureCommand(ExchangeCommand):
    def __init__(self, data: bytes, memory: ExchangeMemory):
        super().__init__(data)

        if self.is_ng:
            self.sig_computation_int = self.data[0]
            if self.sig_computation_int == SignatureComputation.BINARY_ENCODED_PAYLOAD:
                self.sig_computation_str = f"0x{self.sig_computation_int:02x} (BINARY_ENCODED_PAYLOAD)"
            elif self.sig_computation_int == SignatureComputation.DOT_PREFIXED_BASE_64_URL:
                self.sig_computation_str = f"0x{self.sig_computation_int:02x} (DOT_PREFIXED_BASE_64_URL)"
            else:
                self.sig_computation_str = f"0x{self.sig_computation_int:02x} (UNRECOGNIZED)"

            self.sig_encoding_int = self.data[1]
            if self.sig_encoding_int == SignatureEncoding.DER:
                self.sig_encoding_str = f"0x{self.sig_encoding_int:02x} (DER)"
            elif self.sig_encoding_int == SignatureEncoding.PLAIN_R_S:
                self.sig_encoding_str = f"0x{self.sig_encoding_int:02x} (PLAIN_R_S)"
            else:
                self.sig_encoding_str = f"0x{self.sig_encoding_int:02x} (UNRECOGNIZED)"

        else:
            if self.is_swap:
                self.sig_computation_int = SignatureComputation.BINARY_ENCODED_PAYLOAD
            else:
                self.sig_computation_int = SignatureComputation.DOT_PREFIXED_BASE_64_URL

            if self.is_sell:
                self.sig_encoding_int = SignatureEncoding.PLAIN_R_S
            else:
                self.sig_encoding_int = SignatureEncoding.DER

        if self.is_ng:
            self.signature = self.data[2:]
        else:
            self.signature = self.data

        if memory.transaction is not None and memory.partner_key is not None and memory.partner_curve is not None:
            if self.sig_computation_int == SignatureComputation.BINARY_ENCODED_PAYLOAD:
                message = memory.transaction
            else:
                message = b'.' + memory.transaction

            if self.sig_encoding_int == SignatureEncoding.DER:
                der_sig = self.signature
            else:
                r = int.from_bytes(self.signature[:32], 'big')
                s = int.from_bytes(self.signature[32:], 'big')
                der_sig = encode_dss_signature(r, s)

            if signature_tester.check_partner_signature(memory.partner_key, message, der_sig, memory.partner_curve):
                self.sign_check_text = "    (Valid signature of the transaction by the partner key)"
            else:
                self.sign_check_text = "    (/!\\ This is NOT a valid signature of the transaction by the partner key)"
        else:
            self.sign_check_text = "    No transaction to parse"

    def __str__(self):
        strings = [
            super().__str__(),
            summary("Signature by the partner of the proposed transaction"),
            "",
        ]
        if self.is_ng:
            strings += [
                item_str(1, "Signature computation", self.sig_computation_str),
                item_str(1, "Signature encoding", self.sig_encoding_str)
            ]
        strings += [
            item_str(1, "Signature", self.signature.hex()),
            self.sign_check_text,
        ]
        return "\n".join(strings)


class UnpackedDerivationPath:
    def __init__(self, derivation_path: bytes):
        self.valid = False
        self.bitcoin_format = None

        if len(derivation_path) % 4 <= 2:
            if len(derivation_path) % 4 == 2:
                # Bitcoin like derivation path
                self.bitcoin_format = derivation_path[0]
                derivation_path = derivation_path[1:]

            self.derivation_path_length = derivation_path[0]
            derivation_path = derivation_path[1:]
            if self.derivation_path_length == len(derivation_path) / 4:
                self.valid = True
                self.unpacked_derivation_path = "m"
                for chunk in [derivation_path[i:i + 4] for i in range(0, len(derivation_path), 4)]:
                    if chunk != b'':
                        value = int.from_bytes(chunk, byteorder='big')
                        if value & 2**31:
                            value_str = str(value & ~2**31) + "'"
                        else:
                            value_str = str(value)
                        self.unpacked_derivation_path += "/" + value_str

    def __str__(self):
        strings = []
        if not self.valid:
            strings += [
                title(2, "Failed to unpack derivation path, length does not match"),
            ]
        else:
            if self.bitcoin_format is not None:
                strings += [
                    item_str(2, "Bitcoin like format header", self.bitcoin_format),
                ]

            strings += [
                item_str(2, "Unpacked derivation path element number", self.derivation_path_length),
                item_str(2, "Unpacked derivation path", self.unpacked_derivation_path),
            ]
        return "\n".join(strings)


class CheckAddress(ExchangeCommand):
    summary: Optional[str] = None

    def __init__(self, data: bytes, memory: ExchangeMemory):
        super().__init__(data)
        # gathering configuration
        if len(self.data) < 2:
            self.error = True

        self.configuration_length, self.configuration, remaining_apdu = lv_digest(self.data)

        self.ticker_length, self.ticker, remaining_conf = lv_digest(self.configuration)
        self.appname_length, self.appname, remaining_conf = lv_digest(remaining_conf)
        self.subconfiguration_length, subconfig, remaining_conf = lv_digest(remaining_conf)
        if self.subconfiguration_length > 0:
            self.subticker_length, self.subticker, remaining_subconf = lv_digest(subconfig)
            self.coefficient, remaining_subconf = l_digest(remaining_subconf)

        self.signature_header, remaining_apdu = l_digest(remaining_apdu)
        self.signature_length, self.signature, remaining_apdu = lv_digest(remaining_apdu)
        full_signature = self.signature_header.to_bytes(length=1, byteorder='big') \
            + self.signature_length.to_bytes(length=1, byteorder='big') \
            + self.signature
        if signature_tester.check_ledger_prod_signature(self.configuration, full_signature):
            self.sign_check_text = title(1, "(Valid signature of the coin configuration by the Ledger PROD key)")
        elif signature_tester.check_ledger_test_signature(self.configuration, full_signature):
            self.sign_check_text = title(1, "(Valid signature of the coin configuration by the Ledger TEST key)")
        else:
            self.sign_check_text = title(1, "(/!\\ This is NOT a valid signature of the coin configuration)")

        self.raw_derivation_path_length, self.raw_derivation_path, remaining_apdu = lv_digest(remaining_apdu)
        self.unpacked_derivation_path = UnpackedDerivationPath(self.raw_derivation_path)

    def __str__(self):
        strings = [
            super().__str__(),
            summary(self.summary),
            "",
        ]
        if not self.error:
            strings += [
                item_str(1, "Coin configuration length", self.configuration_length),
                item_str(1, "Coin configuration", self.configuration.hex()),
                item_str(2, "Ticker length", self.ticker_length),
                item_str(2, "Ticker", self.ticker.decode()),
                item_str(2, "Application name length", self.appname_length),
                item_str(2, "Application name", self.appname.decode()),
                item_str(2, "Subconfiguration length", self.subconfiguration_length),
            ]
            if self.subconfiguration_length > 0:
                strings += [
                    item_str(3, "Subticker length", self.subticker_length),
                    item_str(3, "Subticker", self.subticker.decode()),
                    item_str(3, "Subconfiguration coefficient", self.coefficient),
                ]
            strings += [
                "",
                item_str(1, "Coin configuration signature header", self.signature_header),
                item_str(1, "Coin configuration signature length", self.signature_length),
                item_str(1, "Coin configuration signature", self.signature.hex()),
                self.sign_check_text,
                "",
                item_str(1, "Raw derivation path length", self.raw_derivation_path_length),
                item_str(1, "Raw derivation path", self.raw_derivation_path.hex()),
                str(self.unpacked_derivation_path),
            ]
        return "\n".join(strings)


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
