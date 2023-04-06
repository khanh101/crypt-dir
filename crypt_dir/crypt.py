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


def aes256_decrypt(
        key: bytes, init_vec: bytes, file_size: int,
        encrypted_read_io: BinaryIO, decrypted_write_io: BinaryIO,
):
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


def read_or_create_key(key_path: str) -> bytes:
    def read_hex_file(path: str) -> bytes:
        with open(path, "r") as f:
            return bytes.fromhex(f.read())

    def write_hex_file(path: str, b: bytes):
        with open(path, "w") as f:
            f.write(b.hex())

    if not os.path.exists(key_path):
        write_hex_file(key_path, os.urandom(KEY_SIZE))

    key = read_hex_file(key_path)
    return key


def make_key_from_password(password: bytes) -> bytes:
    hash = sha1_hash(io.BytesIO(password))
    hash += hash * (KEY_SIZE // HASH_SIZE)
    key = hash[:KEY_SIZE]
    return key
