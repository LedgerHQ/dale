from base import Command, Response


EXCHANGE_CLA = 0xE0


INS = {
    0x02: 'GET_VERSION_COMMAND',
    0x03: 'START_NEW_TRANSACTION_COMMAND',
    0x04: 'SET_PARTNER_KEY_COMMAND',
    0x05: 'CHECK_PARTNER_COMMAND',
    0x06: 'PROCESS_TRANSACTION_RESPONSE_COMMAND',
    0x07: 'CHECK_TRANSACTION_SIGNATURE_COMMAND',
    0x08: 'CHECK_PAYOUT_ADDRESS',
    0x09: 'CHECK_REFUND_ADDRESS',
    0x0A: 'START_SIGNING_TRANSACTION'
}


RATE = {
    0x00: 'FIXED',
    0x01: 'FLOATING'
}


SUBCOMMAND = {
    0x00: 'SWAP',
    0x01: 'SELL',
    0x02: 'FUND'
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


def exchange_factory(data):
    assert data[0] == EXCHANGE_CLA
    assert len(data) > 1
    ins = data[1]
    if ins == 0x03:
        return StartTransactionCommand(data)
    elif ins == 0x04:
        return SetPartnerKeyCommand(data)
    elif ins == 0x05:
        return CheckPartnerCommand(data)
    elif ins == 0x06:
        return ProcessTransactionCommand(data)
    else:
        return ExchangeCommand(data)


class ExchangeResponse(Response):
    def __repr__(self):
        if self.code == 0x9000:
            result = "SUCCESS"
        else:
            result = f"ERROR {ERRORS.get(self.code, 'UNKNOWN')} (0x{self.code.hex()})"
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
    def __repr__(self):
        return "\n".join([
            "="*30,
            f"> {INS[self.ins]} - {RATE[self.rate]} - {SUBCOMMAND[self.subcommand]}"
        ])


class StartTransactionResponse(ExchangeResponse):
    @property
    def transaction_id(self):
        return self.data
    def __repr__(self):
        return "\n".join([
            super().__repr__(),
            raw_hex_str("TRANSACTION_ID", self.transaction_id)
        ])

class StartTransactionCommand(ExchangeCommand):
    @property
    def next(self):
        return StartTransactionResponse

class SetPartnerKeyCommand(ExchangeCommand):
    @property
    def partner_key(self):
        return self.data
    def __repr__(self):
        return "\n".join([
            super().__repr__(),
            raw_hex_str("Partner key", self.partner_key)
        ])

class CheckPartnerCommand(ExchangeCommand):
    @property
    def partner_signature(self):
        return self.data
    def __repr__(self):
        return "\n".join([
            super().__repr__(),
            raw_hex_str("Partner signature", self.partner_signature)
        ])

class ProcessTransactionCommand(ExchangeCommand):
    @property
    def payload_length(self):
        return self.data[0]
    @property
    def payload(self):
        return self.data[1:1+self.payload_length]
    @property
    def fees_offset(self):
        return self.payload_length + 2
    @property
    def fees_length(self):
        return self.data[self.fees_offset - 1]
    @property
    def fees(self):
        return self.data[self.fees_offset:self.fees_offset + self.fees_length]
    def __repr__(self):
        return "\n".join([
            super().__repr__(),
            raw_hex_str("Payload", self.payload),
            raw_hex_str("Fees", self.fees)
        ])
