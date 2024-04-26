from typing import Tuple


def lv_digest(data: bytes) -> Tuple[int, bytes, bytes]:
    if len(data) == 0:
        return (0, b'', b'')
    size = data[0]
    return (size, data[1:1 + size], data[1 + size:])


def l_digest(data: bytes) -> Tuple[int, bytes]:
    return (data[0], data[1:])


def bytes_to_raw_str(b: bytes) -> str:
    return ''.join('{:02x}'.format(x) for x in b)
