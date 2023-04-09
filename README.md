# CRYPT_DIR

- Encrypt all your files and write into another directory if there is update
- Clean the encrypted directory if files or directories have been deleted
- Restore
- Minimize writing to SSDs

# USAGE

- encrypt

```python
# User maintains two directories plain_dir and encrypted_dir
import crypt_dir

plain_dir = "plain"
encrypted_dir = "encrypted"
restored_dir = "restored"

key = crypt_dir.make_key_from_password(b"password1234")

# Delete all files, directories in encrypted_dir that don't exist in the plain_dir
crypt_dir.clean_encrypted_dir(
    plain_dir=plain_dir,
    encrypted_dir=encrypted_dir,
)

# read files in plain_dir, encrypt and write files into encrypted_dir if needed using 12 workers
crypt_dir.update_encrypted_dir(
    key=key,
    plain_dir=plain_dir,
    encrypted_dir=encrypted_dir,
    max_workers=12,
)
```

- restore

```python
import crypt_dir

plain_dir = "plain"
encrypted_dir = "encrypted"
restored_dir = "restored"

key = crypt_dir.make_key_from_password(b"password1234")

# restore all files in encrypted_dir using 12 workers
crypt_dir.restore_encrypted_dir(
    key=key,
    encrypted_dir=encrypted_dir,
    restored_dir=restored_dir,
    max_workers=12,
)
```

- certificate

```python
import crypt_dir

correct_password = b"password123"

cert = crypt_dir.make_certificate(correct_password)
print("cert", cert)

try:
    wrong_password = b"password456"
    _ = crypt_dir.verify_certificate(cert, wrong_password)
except AssertionError as e:
    print("expected assertion error: ", e)

key = crypt_dir.verify_certificate(cert, correct_password)

print("generated key from correct password", key)

```

# INSTALLATION

```shell
pip install --upgrade crypt-dir
```

# DECRYPT IT YOURSELF

## SPECIFICATION 1.*

You don't need to know the specification. For some folks who want to know exactly what happened with their files, here
is the specification for `key_file` and `.enc` files:

- if `key_file` does not exist, `crypt_dir` will create a random key of 32 bytes using `os.urandom` encoded into `hex`

- two algorithms are used in `crypt_dir`: `SHA1` and `AES-256` in `CBC` mode

- encrypted files are updated only if file is modified (mtime changes)

- file is decrypt-able if `signature` matches `key`

- `.enc1` file

    - `header`:
        - `file_sig`: little-endian encoded mtime of file in uint64
        - `key_sig`: `SHA1` bytes of key
        - `file_size`: little-endian encoded file size in uint64
        - `init_vec`: `AES256` initialization vector

    - `file encrypted`: `AES256` file encrypted bytes with chunk size of `2^30`

```
__________________________________________________________________________________
|                          header                           |   encrypted_data   |
|___________________________________________________________|____________________|
|   file_sig   |   key_sig   |   file_size   |   init_vec   |   encrypted_data   |
|   8 bytes    |   20 bytes  |   8 bytes     |   16 bytes   |   n bytes          |
|___________________________________________________________|____________________|
```

## SPECIFICATION 0.*

You don't need to know the specification. For some folks who want to know exactly what happened with their files, here
is the specification for `key_file` and `.enc` files:

- if `key_file` does not exist, `crypt_dir` will create a random key of 32 bytes using `os.urandom` encoded into `hex`

- two algorithms are used in `crypt_dir`: `SHA1` and `AES-256` in `CBC` mode

- encrypted files are updated only if file_hash changes

- file is decrypt-able if `signature` matches `key`

- `.enc` file

    - `signature`: `SHA1` bytes of key
    - `file_hash`: `SHA1` bytes of file
    - `file_size`: little-endian encoded file size in uint64
    - `iv`: `AES256` initialization vector
    - `file encrypted`: `AES256` file encrypted bytes with chunk size of `2^30`

```
|   signature   |   file_hash   |   file_size   |   iv          |   encrypted_data  |
|   20 bytes    |   20 bytes    |   8 bytes     |   16 bytes    |   n bytes         |
```

# UPLOAD

```shell
rm -rf dist crypt_dir.egg-info
python setup.py sdist
twine upload dist/*
```
