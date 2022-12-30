from __future__ import annotations

import concurrent.futures
import sys
from typing import *
import os
import shutil
from .crypt_file import Codec

ENCRYPTED_EXT = "enc"


def delete_if_ok(encrypted_path: str):
    if os.path.exists(encrypted_path):
        if os.path.isfile(encrypted_path):
            os.remove(encrypted_path)
            sys.stdout.write(f"deleted: {encrypted_path}\n")
        if os.path.isdir(encrypted_path):
            shutil.rmtree(encrypted_path)
            sys.stdout.write(f"deleted: {encrypted_path}\n")


def walk_file(path: str, skip_mount: bool = True, skip_link: bool = True) -> Iterator[str]:
    assert os.path.isabs(path)
    if skip_mount and os.path.ismount(path):
        return
    if skip_link and os.path.islink(path):
        return
    if os.path.isfile(path):
        yield path
    if os.path.isdir(path):
        for name in os.listdir(path):
            yield from walk_file(os.path.join(path, name), skip_mount, skip_link)


def walk_dir(path: str, skip_mount: bool = True, skip_link: bool = True) -> Iterator[str]:
    assert os.path.isabs(path)
    if skip_mount and os.path.ismount(path):
        return
    if skip_link and os.path.islink(path):
        return
    if os.path.isdir(path):
        # bottom up
        for name in os.listdir(path):
            yield from walk_dir(os.path.join(path, name), skip_mount, skip_link)
        yield path


def plain_path_to_encrypted_path(plain_dir: str, encrypted_dir: str, plain_path: str) -> str:
    return plain_path.replace(plain_dir, encrypted_dir) + f".{ENCRYPTED_EXT}"


def plain_dir_to_encrypted_dir(plain_dir: str, encrypted_dir: str, plain_path: str) -> str:
    return plain_path.replace(plain_dir, encrypted_dir)


def encrypted_path_to_plain_path(plain_dir: str, encrypted_dir: str, encrypted_path: str) -> str:
    return encrypted_path.replace(encrypted_dir, plain_dir)[:-len(f".{ENCRYPTED_EXT}")]


def encrypted_dir_to_plain_dir(plain_dir: str, encrypted_dir: str, encrypted_path: str) -> str:
    return encrypted_path.replace(encrypted_dir, plain_dir)


def clean_encrypted_dir(plain_dir: str, encrypted_dir: str):
    """
    delete files, directories in encrypted_dir if they do not appear in the plain_dir
    :param plain_dir:
    :param encrypted_dir:
    :return:
    """
    plain_dir = os.path.abspath(plain_dir)
    encrypted_dir = os.path.abspath(encrypted_dir)
    for encrypted_path in walk_dir(encrypted_dir):
        plain_path = encrypted_dir_to_plain_dir(plain_dir, encrypted_dir, encrypted_path)
        if not os.path.exists(plain_path):
            delete_if_ok(encrypted_path)
    for encrypted_path in walk_file(encrypted_dir):
        if not encrypted_path.endswith(f".{ENCRYPTED_EXT}"):
            continue
        plain_path = encrypted_path_to_plain_path(plain_dir, encrypted_dir, encrypted_path)
        if not os.path.exists(plain_path):
            delete_if_ok(encrypted_path)


def copy_dir_structure(dir_in: str, dir_out: str):
    dir_in = os.path.abspath(dir_in)
    dir_out = os.path.abspath(dir_out)
    for path_in in walk_dir(dir_in):
        path_out = path_in.replace(dir_in, dir_out)
        if not os.path.exists(path_out):
            os.makedirs(path_out)


def write_encrypted_dir(key_file: str, plain_dir: str, encrypted_dir: str, max_workers: int | None = None):
    """
    read files in plain_dir, encrypt and write files into encrypted_dir if needed
    :param plain_dir:
    :param encrypted_dir:
    :param key_file:
    :param max_workers:
    :return:
    """
    plain_dir = os.path.abspath(plain_dir)
    encrypted_dir = os.path.abspath(encrypted_dir)
    codec = Codec(key_file)
    copy_dir_structure(plain_dir, encrypted_dir)

    def make_dir_and_encrypt_file_if_needed(plain_path: str):
        encrypted_path = plain_path_to_encrypted_path(plain_dir, encrypted_dir, plain_path)
        try:
            os.makedirs(os.path.dirname(encrypted_path))
        except FileExistsError:
            pass
        encrypted = codec.encrypt_file_if_needed(plain_path, encrypted_path)
        return encrypted, encrypted_path

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_list = [executor.submit(make_dir_and_encrypt_file_if_needed, plain_path) for plain_path in
                       walk_file(plain_dir)]
        for future in concurrent.futures.as_completed(future_list):
            encrypted, encrypted_path = future.result()
            if encrypted:
                sys.stdout.write(f"encrypted: {encrypted_path}\n")


def is_encrypted_file(path: str) -> bool:
    return path.endswith(".encrypted")


def read_encrypted_dir(key_file: str, encrypted_dir: str, plain_dir: str, max_workers: int | None = None):
    """
    decrypt all files in encrypted_dir
    :param plain_dir:
    :param encrypted_dir:
    :param key_file:
    :param max_workers:
    :return:
    """
    encrypted_dir = os.path.abspath(encrypted_dir)
    plain_dir = os.path.abspath(plain_dir)
    codec = Codec(key_file)
    copy_dir_structure(encrypted_dir, plain_dir)

    def decrypt_file_if_needed(encrypted_path: str):
        plain_path = encrypted_path_to_plain_path(plain_dir, encrypted_dir, encrypted_path)
        try:
            os.makedirs(os.path.dirname(plain_path))
        except FileExistsError:
            pass
        decrypted = codec.decrypt_file_if_needed(encrypted_path, plain_path)
        return decrypted, plain_path

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_list = [executor.submit(decrypt_file_if_needed, encrypted_path) for encrypted_path in
                       walk_file(encrypted_dir) if is_encrypted_file(encrypted_path)]
        for future in concurrent.futures.as_completed(future_list):
            decrypted, path = future.result()
            if decrypted:
                sys.stdout.write(f"decrypted: {path}\n")
