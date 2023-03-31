#!/usr/bin/env python
import io
import os
import struct
from typing import BinaryIO, Optional

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1

HASH_SIZE = 20  # size of hash value in bytes
BLOCK_SIZE = AES.block_size  # size of AES block in bytes
KEY_SIZE = 32  # size of AES key in bytes
UINT64_SIZE = 8  # size of uint64 in bytes
AES_MODE = AES.MODE_CBC  # cipher block chaining
CHUNK_SIZE = 2 ** 30  # 1 GB # chunk size to read from io in bytes
IV_SIZE = 16  # size of iv in bytes


def get_mtime(path: str) -> int:
    return os.stat(path=path).st_mtime_ns


def set_mtime(path: str, mtime: int, atime: Optional[int] = None):
    if atime is None:
        atime = mtime
    os.utime(path=path, ns=(atime, mtime))


def random_bytes(count: int = 1) -> bytes:
    return os.urandom(count)


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


def sha1_hash(f_in: BinaryIO) -> bytes:
    h = SHA1.new()
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if len(chunk) == 0:
            b = h.digest()
            assert len(b) == HASH_SIZE
            return b
        h.update(chunk)


def aes256_encrypt(key: bytes, iv: bytes, plain_read_io: BinaryIO, encrypted_write_io: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(iv) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, iv)
    while True:
        chunk = plain_read_io.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        if len(chunk) % BLOCK_SIZE != 0:
            chunk += b"\0" * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)  # padded with 0s until BLOCK_SIZE
        b = aes.encrypt(chunk)
        encrypted_write_io.write(b)


def aes256_decrypt(key: bytes, iv: bytes, size: int, encrypted_read_io: BinaryIO, decrypted_write_io: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(iv) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, iv)
    remaining_size = size
    while True:
        chunk = encrypted_read_io.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        b = aes.decrypt(chunk)
        if remaining_size < len(b):
            b = b[:remaining_size]
        decrypted_write_io.write(b)
        remaining_size -= len(b)


def aes256_encrypt_file_if_needed(key: bytes, sig: bytes, plain_path: str, encrypted_path: str) -> bool:
    plain_mtime = get_mtime(plain_path)
    # check file updated
    if os.path.exists(encrypted_path):
        encrypted_mtime = get_mtime(encrypted_path)
        if plain_mtime == encrypted_mtime:
            return False

    # encrypted file will be updated regardless its mtime is sooner or later
    # encrypt
    iv = random_bytes(IV_SIZE)
    size = os.path.getsize(plain_path)
    with open(plain_path, "rb") as plain_f, open(encrypted_path, "wb") as encrypted_f:
        encrypted_f.write(sig)  # 20 bytes - signature
        encrypted_f.write(uint64_to_bytes(size))  # 8 bytes - little endian of file size in uint64
        encrypted_f.write(iv)  # 16 bytes - initialization vector
        aes256_encrypt(key=key, iv=iv, plain_read_io=plain_f, encrypted_write_io=encrypted_f)
    # set mtime after file is closed
    set_mtime(path=encrypted_path, mtime=plain_mtime)
    return True


def aes256_decrypt_file(key: bytes, sig: bytes, encrypted_path: str, decrypted_path: str):
    with open(encrypted_path, "rb") as encrypted_f, open(decrypted_path, "wb") as plain_f:
        encrypted_sig = encrypted_f.read(HASH_SIZE)
        if encrypted_sig != sig:
            raise RuntimeError(f"signature does not match for {encrypted_path}")
        size = bytes_to_uint64(encrypted_f.read(UINT64_SIZE))
        iv = encrypted_f.read(BLOCK_SIZE)
        aes256_decrypt(key=key, iv=iv, size=size, encrypted_read_io=encrypted_f, decrypted_write_io=plain_f)
    # set mtime after file is closed
    set_mtime(path=decrypted_path, mtime=get_mtime(encrypted_path))


class Codec:
    def __init__(self, key_path: str):
        """
        Codec: encrypt and decrypt a file
        encrypted file structure
        |signature|file_size|iv|encrypted_data|

        :param key_path: path to key file in hex
        """
        if not os.path.exists(key_path):
            write_hex_file(key_path, random_bytes(KEY_SIZE))
        self.key = read_hex_file(key_path)
        self.sig = sha1_hash(io.BytesIO(self.key))

    def encrypt_file_if_needed(self, plain_path: str, encrypted_path: str) -> bool:
        return aes256_encrypt_file_if_needed(
            key=self.key,
            sig=self.sig,
            plain_path=plain_path,
            encrypted_path=encrypted_path,
        )

    def decrypt_file(self, encrypted_path: str, decrypted_path: str):
        aes256_decrypt_file(
            key=self.key,
            sig=self.sig,
            encrypted_path=encrypted_path,
            decrypted_path=decrypted_path,
        )


if __name__ == "__main__":
    key = random_bytes(KEY_SIZE)
    sig = sha1_hash(io.BytesIO(key))
    iv = random_bytes(IV_SIZE)
    plain = b"hello world, this is an example message"
    print("plain", plain)

    encrypted_io = io.BytesIO()
    aes256_encrypt(key, iv, io.BytesIO(plain), encrypted_io)
    encrypted_io.seek(0)
    encrypted = encrypted_io.read()
    print("encrypted", encrypted)

    encrypted_io.seek(0)
    decrypted_io = io.BytesIO()
    aes256_decrypt(key, iv, len(plain), encrypted_io, decrypted_io)
    decrypted_io.seek(0)
    decrypted = decrypted_io.read()
    print("decrypt", decrypted)
    assert plain == decrypted
