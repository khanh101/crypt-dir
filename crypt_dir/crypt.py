import io
from typing import BinaryIO

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1

HASH_SIZE = 20  # size of hash value in bytes
BLOCK_SIZE = AES.block_size  # size of AES block in bytes
KEY_SIZE = 32  # size of AES key in bytes
AES_MODE = AES.MODE_CBC  # cipher block chaining
CHUNK_SIZE = 2 ** 30  # 1 GB # chunk size to read from io in bytes

assert BLOCK_SIZE == 16
assert CHUNK_SIZE % BLOCK_SIZE == 0


def sha1_hash(f_in: BinaryIO) -> bytes:
    h = SHA1.new()
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if len(chunk) == 0:
            b = h.digest()
            assert len(b) == HASH_SIZE
            return b
        h.update(chunk)


def aes256_encrypt(
        key: bytes, init_vec: bytes,
        plain_read_io: BinaryIO, encrypted_write_io: BinaryIO,
):
    assert len(init_vec) == BLOCK_SIZE
    assert len(key) == KEY_SIZE

    aes = AES.new(key, AES_MODE, init_vec)
    while True:
        chunk = plain_read_io.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        if len(chunk) % BLOCK_SIZE != 0:
            chunk += b"\0" * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)  # pad 0s until multiples of BLOCK_SIZE

        b = aes.encrypt(chunk)

        encrypted_write_io.write(b)


def aes256_decrypt(
        key: bytes, init_vec: bytes, file_size: int,
        encrypted_read_io: BinaryIO, decrypted_write_io: BinaryIO,
):
    assert len(init_vec) == BLOCK_SIZE
    assert len(key) == KEY_SIZE

    aes = AES.new(key, AES_MODE, init_vec)
    remaining_size = file_size
    while remaining_size > 0:
        chunk = encrypted_read_io.read(CHUNK_SIZE)
        assert len(chunk) == CHUNK_SIZE, "corrupted_file"

        b = aes.decrypt(chunk)

        if remaining_size < len(b):
            b = b[:remaining_size]
        remaining_size -= len(b)

        decrypted_write_io.write(b)


def make_key_from_password(password: bytes) -> bytes:
    hash = sha1_hash(io.BytesIO(password))
    hash += hash * (KEY_SIZE // HASH_SIZE)
    key = hash[:KEY_SIZE]
    return key
