#!/usr/bin/env python
from __future__ import annotations

import io
import os

from .crypt import aes256_encrypt, aes256_decrypt, sha1_hash, random_bytes, IV_SIZE, BLOCK_SIZE, KEY_SIZE
from .sig import get_file_signature, FILE_SIGNATURE_SIZE, get_key_signature, KEY_SIGNATURE_SIZE, set_file_signature
from .util import uint64_to_bytes, bytes_to_uint64, write_hex_file, read_hex_file, UINT64_SIZE


def aes256_encrypt_file_if_needed(
        key: bytes, plain_path: str, encrypted_path: str,
        key_sig: bytes | None = None,
) -> bool:
    if key_sig is None:
        key_sig = get_key_signature(key)
    plain_file_sig = get_file_signature(plain_path)
    # check file updated
    if os.path.exists(encrypted_path):
        with open(encrypted_path, "rb") as f:
            encrypted_file_sig = f.read(FILE_SIGNATURE_SIZE)
        if plain_file_sig == encrypted_file_sig:
            return False

    # encrypted file will be updated regardless its mtime is sooner or later
    # encrypt
    iv = random_bytes(IV_SIZE)
    size = os.path.getsize(plain_path)
    with open(plain_path, "rb") as plain_f, open(encrypted_path, "wb") as encrypted_f:
        encrypted_f.write(plain_file_sig)  # 8 bytes - file signature - little endian of mtime in uint64
        encrypted_f.write(key_sig)  # 20 bytes - key signature
        encrypted_f.write(uint64_to_bytes(size))  # 8 bytes - little endian of file size in uint64
        encrypted_f.write(iv)  # 16 bytes - initialization vector
        aes256_encrypt(key=key, iv=iv, plain_read_io=plain_f, encrypted_write_io=encrypted_f)
    return True


def aes256_decrypt_file(
        key: bytes, encrypted_path: str, decrypted_path: str,
        key_sig: bytes | None = None,
):
    if key_sig is None:
        key_sig = get_key_signature(key)
    with open(encrypted_path, "rb") as encrypted_f, open(decrypted_path, "wb") as decrypted_f:
        encrypted_file_sig = encrypted_f.read(FILE_SIGNATURE_SIZE)  # 8 bytes - file signature - little endian of mtime in uint64
        encrypted_key_sig = encrypted_f.read(KEY_SIGNATURE_SIZE)  # 20 bytes - key signature
        if encrypted_key_sig != key_sig:
            raise RuntimeError(f"signature does not match for {encrypted_path}")
        size = bytes_to_uint64(encrypted_f.read(UINT64_SIZE))  # 8 bytes - little endian of file size in uint64
        iv = encrypted_f.read(BLOCK_SIZE)  # 16 bytes - initialization vector
        aes256_decrypt(key=key, iv=iv, size=size, encrypted_read_io=encrypted_f, decrypted_write_io=decrypted_f)
    # set file signature
    set_file_signature(path=decrypted_path, sig=encrypted_file_sig)


class Codec:
    def __init__(self, key_path: str):
        """
        Codec: encrypt and decrypt a file
        encrypted file structure
        |file_signature|key_signature|file_size|iv|encrypted_data|

        :param key_path: path to key file in hex
        """
        if not os.path.exists(key_path):
            write_hex_file(key_path, random_bytes(KEY_SIZE))
        self.key = read_hex_file(key_path)
        self.sig = sha1_hash(io.BytesIO(self.key))

    def encrypt_file_if_needed(self, plain_path: str, encrypted_path: str) -> bool:
        return aes256_encrypt_file_if_needed(
            key=self.key,
            plain_path=plain_path,
            encrypted_path=encrypted_path,
            key_sig=self.sig,
        )

    def decrypt_file(self, encrypted_path: str, decrypted_path: str):
        aes256_decrypt_file(
            key=self.key,
            encrypted_path=encrypted_path,
            decrypted_path=decrypted_path,
            key_sig=self.sig,
        )
