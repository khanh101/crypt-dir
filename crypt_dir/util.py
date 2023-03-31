import struct

UINT64_SIZE = 8  # size of uint64 in bytes


def read_hex_file(path: str) -> bytes:
    with open(path, "r") as f:
        return bytes.fromhex(f.read())


def write_hex_file(path: str, b: bytes):
    with open(path, "w") as f:
        f.write(b.hex())


def uint64_to_bytes(i: int) -> bytes:
    return struct.pack("<Q", i)  # little endian, uint64


def bytes_to_uint64(b: bytes) -> int:
    return struct.unpack("<Q", b)[0]  # little endian, uint64
