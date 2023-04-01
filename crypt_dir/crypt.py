import io
import os
from typing import BinaryIO

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1

HASH_SIZE = 20  # size of hash value in bytes
BLOCK_SIZE = AES.block_size  # size of AES block in bytes
KEY_SIZE = 32  # size of AES key in bytes
AES_MODE = AES.MODE_CBC  # cipher block chaining
CHUNK_SIZE = 2 ** 30  # 1 GB # chunk size to read from io in bytes


def random_bytes(count: int = 1) -> bytes:
    return os.urandom(count)


def sha1_hash(f_in: BinaryIO) -> bytes:
    h = SHA1.new()
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if len(chunk) == 0:
            b = h.digest()
            assert len(b) == HASH_SIZE
            return b
        h.update(chunk)


def aes256_encrypt(key: bytes, init_vec: bytes, plain_read_io: BinaryIO, encrypted_write_io: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(init_vec) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, init_vec)
    while True:
        chunk = plain_read_io.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        if len(chunk) % BLOCK_SIZE != 0:
            chunk += b"\0" * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)  # padded with 0s until BLOCK_SIZE
        b = aes.encrypt(chunk)
        encrypted_write_io.write(b)


def aes256_decrypt(key: bytes, init_vec: bytes, file_size: int, encrypted_read_io: BinaryIO, decrypted_write_io: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(init_vec) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, init_vec)
    remaining_size = file_size
    while True:
        chunk = encrypted_read_io.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        b = aes.decrypt(chunk)
        if remaining_size < len(b):
            b = b[:remaining_size]
        decrypted_write_io.write(b)
        remaining_size -= len(b)


if __name__ == "__main__":
    key = random_bytes(KEY_SIZE)
    sig = sha1_hash(io.BytesIO(key))
    init_vec = random_bytes(BLOCK_SIZE)
    plain = b"hello world, this is an example message"
    print("plain", plain)

    encrypted_io = io.BytesIO()
    aes256_encrypt(key, init_vec, io.BytesIO(plain), encrypted_io)
    encrypted_io.seek(0)
    encrypted = encrypted_io.read()
    print("encrypted", encrypted)

    encrypted_io.seek(0)
    decrypted_io = io.BytesIO()
    aes256_decrypt(key, init_vec, len(plain), encrypted_io, decrypted_io)
    decrypted_io.seek(0)
    decrypted = decrypted_io.read()
    print("decrypt", decrypted)
    assert plain == decrypted
