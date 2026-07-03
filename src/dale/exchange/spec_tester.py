from typing import Dict, Optional, Tuple, Type, Union


# Mirror of app-exchange/src/proto/protocol.options (nanopb max_size).
# Each entry maps a field to (max_size, kind).
# For 'str' fields nanopb max_size counts the NUL terminator, so the usable
# payload is max_size - 1 bytes. For 'bytes' fields max_size is the raw capacity.
FIELD_MAX_SIZE: Dict[str, Dict[str, Tuple[int, Type]]] = {
    "NewTransactionResponse": {
        "payin_address": (151, str),
        "payin_extra_id": (20, str),
        "payin_extra_data": (37, bytes),
        "refund_address": (151, str),
        "refund_extra_id": (20, str),
        "payout_address": (151, str),
        "payout_extra_id": (20, str),
        "currency_from": (10, str),
        "currency_to": (10, str),
        "amount_to_provider": (16, bytes),
        "amount_to_wallet": (16, bytes),
        "device_transaction_id": (11, str),
        "device_transaction_id_ng": (32, bytes),
    },
    "NewSellResponse": {
        "trader_email": (50, str),
        "in_currency": (10, str),
        "in_amount": (16, bytes),
        "in_address": (151, str),
        "in_extra_id": (20, str),
        "out_currency": (10, str),
        "device_transaction_id": (32, bytes),
    },
    "NewFundResponse": {
        "user_id": (50, str),
        "account_name": (50, str),
        "in_currency": (10, str),
        "in_amount": (16, bytes),
        "in_address": (151, str),
        "in_extra_id": (20, str),
        "device_transaction_id": (32, bytes),
    },
    "UDecimal": {
        "coefficient": (16, bytes),
    },
}


def check_field_size(message_name: str,
                     field_name: str,
                     value: Union[str, bytes]) -> Optional[Tuple[int, int, bool]]:
    """Compare a decoded protobuf field against its spec max_size.

    Returns (actual_size, max_usable_size, is_over_spec), or None when the
    field is not part of the known spec.
    """
    entry = FIELD_MAX_SIZE.get(message_name, {}).get(field_name)
    if entry is None:
        return None
    max_size, _ = entry
    if isinstance(value, str):
        actual_size = len(value.encode())
        max_usable = max_size - 1
    else:
        actual_size = len(value)
        max_usable = max_size
    return (actual_size, max_usable, actual_size > max_usable)
