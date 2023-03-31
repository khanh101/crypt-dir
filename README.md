# CRYPT_DIR

- Encrypt all your files in a directory and write into another directory if needed
- Clean the encrypted directory if files or directories have been deleted
- Decrypt all your files in a directory and write into another directory if needed
- Minimize writing to SSDs

# INSTALLATION

```shell
pip install --upgrade crypt-dir
```

# DECRYPT IT YOURSELF - SPECIFICATION 0.*

You don't need to know the specification. For some folks who want to know exactly what happened with their files, here is the specification for `key_file` and `.enc` files:

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

# DECRYPT IT YOURSELF - SPECIFICATION 1.*

You don't need to know the specification. For some folks who want to know exactly what happened with their files, here is the specification for `key_file` and `.enc` files:

- if `key_file` does not exist, `crypt_dir` will create a random key of 32 bytes using `os.urandom` encoded into `hex`

- two algorithms are used in `crypt_dir`: `SHA1` and `AES-256` in `CBC` mode

- encrypted files are updated only if file is modified (mtime changes) 

- file is decrypt-able if `signature` matches `key`

- `.enc1` file

  - `signature`: `SHA1` bytes of key
  - `file_size`: little-endian encoded file size in uint64
  - `iv`: `AES256` initialization vector
  - `file encrypted`: `AES256` file encrypted bytes with chunk size of `2^30`

```
|   signature   |   file_size   |   iv          |   encrypted_data  |
|   20 bytes    |   8 bytes     |   16 bytes    |   n bytes         |
```

# UPLOAD

```shell
rm -rf dist crypt_dir.egg-info
python setup.py sdist
twine upload dist/*
```
