import struct
from typing import List


def mix(buffer: bytes, append_size: bool) -> List[int]:
    chunks = [buffer[i:i + 4] for i in range(0, len(buffer), 4)]
    res = []
    for chunk in chunks:
        padded = chunk.ljust(4, b'\x00')
        u32_val = struct.unpack('<I', padded)[0]
        res.append(u32_val)
    if append_size:
        res.append(len(buffer))
    return res


def splite(buffer: List[int], include_size: bool) -> bytes:
    if not buffer:
        return b''
    if include_size:
        size_record = buffer[-1]
        expected_size = (len(buffer) - 1) * 4
        if not (expected_size - 3 <= size_record <= expected_size):
            return b''
        buffer = buffer[:-1]
    byte_arr = bytearray()
    for u32_val in buffer:
        byte_arr.extend(struct.pack('<I', u32_val))
    if include_size:
        byte_arr = byte_arr[:size_record]
    return bytes(byte_arr)


def x_encode(msg: str, key: str) -> bytes:
    if not msg:
        return b''
    msg_u32 = mix(msg.encode('utf-8'), append_size=True)
    key_u32 = mix(key.encode('utf-8'), append_size=False)
    len_msg = len(msg_u32)
    last = len_msg - 1
    right = msg_u32[last]
    c = 0x9e3779b9
    d = 0
    count = 6 + 52 // len_msg
    for _ in range(count):
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        for p in range(len_msg):
            left = msg_u32[(p + 1) % len_msg]
            right = (
                            ((right >> 5) ^ (left << 2)) +
                            (((left >> 3) ^ (right << 4)) ^ ((d ^ left))) +
                            (key_u32[(p & 3) ^ e] ^ right) +
                            msg_u32[p]
                    ) & 0xFFFFFFFF
            msg_u32[p] = right
    return splite(msg_u32, include_size=False)
