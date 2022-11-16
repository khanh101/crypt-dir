import io
import os
import struct
from typing import BinaryIO

# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1

HASH_SIZE = 20  # size of hash value in bytes
BLOCK_SIZE = AES.block_size  # size of AES block in bytes
KEY_SIZE = 32  # size of AES key in bytes
UINT64_SIZE = 8  # size of uint64 in bytes
AES_MODE = AES.MODE_CBC  # cipher block chaining
CHUNK_SIZE = 2 ** 30  # 1 GB # chunk size to read from io in bytes


def verify(plain: bytes, encrypted: bytes) -> bool:
    return sha1_hash(io.BytesIO(plain)) == io.BytesIO(encrypted).read(2 * HASH_SIZE)[HASH_SIZE:]


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
        b = f_in.read(CHUNK_SIZE)
        if len(b) == 0:
            b = h.digest()
            assert len(b) == HASH_SIZE
            return b
        h.update(b)


def sha1_hash_file(path_in: str) -> bytes:
    """
    no need to cache here
    a file is hashed at most once in Codec.encrypt_file_if_needed
    """
    with open(path_in, "rb") as f_in:
        return sha1_hash(f_in)


def aes256_encrypt(key: bytes, iv: bytes, f_in: BinaryIO, f_out: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(iv) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, iv)
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        if len(chunk) % BLOCK_SIZE != 0:
            chunk += b"\0" * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)  # padded with 0 to equal BLOCK_SIZE
        b = aes.encrypt(chunk)
        f_out.write(b)


def aes256_decrypt(key: bytes, iv: bytes, size: int, f_in: BinaryIO, f_out: BinaryIO):
    assert BLOCK_SIZE == 16
    assert CHUNK_SIZE % BLOCK_SIZE == 0
    assert len(iv) == BLOCK_SIZE
    assert len(key) == KEY_SIZE
    aes = AES.new(key, AES_MODE, iv)
    remaining_size = size
    while True:
        chunk = f_in.read(CHUNK_SIZE)
        if len(chunk) == 0:
            return
        b = aes.decrypt(chunk)
        if remaining_size < len(b):
            b = b[:remaining_size]
        f_out.write(b)
        remaining_size -= len(b)


class Codec:
    def __init__(self, key_file: str):
        """
        Codec: encrypt and decrypt a file
        encrypted file structure
            |key_hash| |file_hash| |file_size| |iv| |encrypted_data|


        :param key_file: path to key file in hex
        """
        if not os.path.exists(key_file):
            write_hex_file(key_file, random_bytes(KEY_SIZE))
        self.key = read_hex_file(key_file)
        self.hash = sha1_hash(io.BytesIO(self.key))

    def encrypt_file_if_needed(self, plain_path: str, encrypt_path: str) -> bool:
        iv = random_bytes(16)
        size = os.path.getsize(plain_path)
        file_hash_plain = sha1_hash_file(plain_path)
        # skip if file is encrypted and not changed
        if os.path.exists(encrypt_path):
            with open(encrypt_path, "rb") as f_encrypt:
                key_hash_encrypt = f_encrypt.read(HASH_SIZE)
                file_hash_encrypt = f_encrypt.read(HASH_SIZE)
                if key_hash_encrypt == self.hash and file_hash_encrypt == file_hash_plain:
                    return False  # skipped

        with open(plain_path, "rb") as f_plain, open(encrypt_path, "wb") as f_encrypt:
            f_encrypt.write(self.hash)
            f_encrypt.write(file_hash_plain)
            f_encrypt.write(uint64_to_bytes(size))
            f_encrypt.write(iv)
            aes256_encrypt(self.key, iv, f_plain, f_encrypt)
        return True

    def decrypt_file_if_needed(self, encrypt_path: str, plain_path: str) -> bool:
        with open(encrypt_path, "rb") as f_encrypt:
            key_hash_encrypt = f_encrypt.read(HASH_SIZE)
            file_hash_encrypt = f_encrypt.read(HASH_SIZE)
        if key_hash_encrypt != self.hash:
            raise RuntimeError("decrypt_file: key not compatible")

        if os.path.exists(plain_path):
            file_hash_plain = sha1_hash_file(plain_path)
            if file_hash_plain == file_hash_encrypt:
                return False  # skipped

        with open(encrypt_path, "rb") as f_encrypt, open(plain_path, "wb") as f_plain:
            file_hash_encrypt = f_encrypt.read(HASH_SIZE)
            key_hash_encrypt = f_encrypt.read(HASH_SIZE)
            size = bytes_to_uint64(f_encrypt.read(UINT64_SIZE))
            iv = f_encrypt.read(BLOCK_SIZE)
            aes256_decrypt(self.key, iv, size, f_encrypt, f_plain)
        return True

    def encrypt(self, plain: bytes) -> bytes:
        iv = random_bytes(16)
        size = len(plain)

        file_hash = sha1_hash(io.BytesIO(plain))
        encrypted_io = io.BytesIO()
        encrypted_io.write(self.hash)
        encrypted_io.write(file_hash)
        encrypted_io.write(uint64_to_bytes(size))
        encrypted_io.write(iv)
        aes256_encrypt(self.key, iv, io.BytesIO(plain), encrypted_io)
        encrypted_io.seek(0)
        encrypted = encrypted_io.read()
        return encrypted

    def decrypt(self, encrypted: bytes) -> bytes:
        encrypted_io = io.BytesIO(encrypted)
        key_hash = encrypted_io.read(HASH_SIZE)
        if key_hash != self.hash:
            return b""
        file_hash = encrypted_io.read(HASH_SIZE)
        size = bytes_to_uint64(encrypted_io.read(UINT64_SIZE))
        iv = encrypted_io.read(BLOCK_SIZE)
        decrypted_io = io.BytesIO()
        aes256_decrypt(self.key, iv, size, encrypted_io, decrypted_io)
        decrypted_io.seek(0)
        decrypted = decrypted_io.read()
        return decrypted


if __name__ == "__main__":
    codec = Codec("key.txt")
    plain = b"hello world, this is an example message"
    # encrypt
    encrypted = codec.encrypt(plain)
    # hash
    assert verify(plain, encrypted)
    assert not verify(plain + b"\1", encrypted)
    assert len(Codec("anotherkey.txt").decrypt(encrypted)) == 0
    # decrypt
    decrypted = codec.decrypt(encrypted)
    assert decrypted == plain

    if not os.path.exists("plain.txt"):
        with open("plain.txt", "wb") as f:
            f.write(plain)

    encrypted = codec.encrypt_file_if_needed("plain.txt", "encrypted.txt")
    if not encrypted:
        print("skipped due to encrypted file exists and plain file unchanged")

    codec.decrypt_file_if_needed("encrypted.txt", "decrypted.txt")
