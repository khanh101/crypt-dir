#!/usr/bin/env python
from __future__ import annotations

import io
import os
from dataclasses import dataclass
from typing import BinaryIO

from .crypt import aes256_encrypt, aes256_decrypt, sha1_hash, random_bytes, IV_SIZE, KEY_SIZE
from .sig import get_file_signature, FILE_SIGNATURE_SIZE, get_key_signature, KEY_SIGNATURE_SIZE, set_file_signature
from .util import uint64_to_bytes, bytes_to_uint64, write_hex_file, read_hex_file, UINT64_SIZE


@dataclass
class Header:
    file_sig: bytes
    key_sig: bytes
    file_size: int
    iv: bytes


def read_header(read_io: BinaryIO) -> Header:
    file_sig = read_io.read(FILE_SIGNATURE_SIZE)
    key_sig = read_io.read(KEY_SIGNATURE_SIZE)
    file_size = bytes_to_uint64(read_io.read(UINT64_SIZE))
    iv = read_io.read(IV_SIZE)
    return Header(file_sig=file_sig, key_sig=key_sig, file_size=file_size, iv=iv)


def write_header(write_io: BinaryIO, header: Header):
    write_io.write(header.file_sig)
    write_io.write(header.key_sig)
    write_io.write(uint64_to_bytes(header.file_size))
    write_io.write(header.iv)


def aes256_encrypt_file_if_needed(
        key: bytes, plain_path: str, encrypted_path: str,
        key_sig: bytes | None = None,
) -> bool:
    if key_sig is None:
        key_sig = get_key_signature(key)
    file_sig = get_file_signature(plain_path)
    # check file updated
    if os.path.exists(encrypted_path):
        with open(encrypted_path, "rb") as f:
            header = read_header(f)
        if file_sig == header.file_sig:
            return False

    # encrypted file will be updated regardless its mtime is sooner or later
    # encrypt
    iv = random_bytes(IV_SIZE)
    file_size = os.path.getsize(plain_path)
    with open(plain_path, "rb") as plain_f, open(encrypted_path, "wb") as encrypted_f:
        write_header(write_io=encrypted_f, header=Header(
            file_sig=file_sig,
            key_sig=key_sig,
            file_size=file_size,
            iv=iv,
        ))
        aes256_encrypt(key=key, iv=iv, plain_read_io=plain_f, encrypted_write_io=encrypted_f)
    return True


def aes256_decrypt_file(
        key: bytes, encrypted_path: str, decrypted_path: str,
        key_sig: bytes | None = None,
):
    if key_sig is None:
        key_sig = get_key_signature(key)
    with open(encrypted_path, "rb") as encrypted_f, open(decrypted_path, "wb") as decrypted_f:
        header = read_header(encrypted_f)
        if header.key_sig != key_sig:
            raise RuntimeError(f"signature does not match for {encrypted_path}")
        aes256_decrypt(key=key, iv=header.iv, file_size=header.file_size, encrypted_read_io=encrypted_f, decrypted_write_io=decrypted_f)
    # set file signature
    set_file_signature(path=decrypted_path, sig=header.file_sig)


class Codec:
    def __init__(self, key_path: str):
        """
        Codec: encrypt and decrypt a file
        encrypted file structure
        |file_sig|key_sig|file_size|iv|encrypted_data|

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
