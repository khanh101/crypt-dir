# CRYPT_DIR

- Encrypt all your files in a directory and write into another directory if needed
- Clean the encrypted directory if files or directories have been deleted
- Decrypt all your files in a directory and write into another directory if needed

# INSTALLATION

```shell
pip install --upgrade crypt-dir
```

# DECRYPT IT YOURSELF - SPECIFICATION

You don't need to know the specification. For some folks who want to know exactly what happened with their files, here is the specification for `key_file` and `.enc` files:

- if `key_file` does not exist, `crypt_dir` will create a random key of 32 bytes using `os.urandom` encoded into `hex`

- two algorithms are used in `crypt_dir`: `SHA1` and `AES-256` in `CBC` mode

- `.enc` file

    - `key_hash`: `SHA1` bytes of key
    - `file_hash`: `SHA1` bytes of file
    - `file_size`: little-endian encoded file size in uint64
    - `iv`: `AES256` initialization vector
    - `file encrypted`: `AES256` file encrypted bytes with chunk size of `2^30`
```
|   key_hash    |   file hash   |   file size   |   iv          |   file encrypted  |
|   20 bytes    |   20 bytes    |   8 bytes     |   16 bytes    |   n bytes         |
```


# UPLOAD

```shell
rm -rf dist crypt_dir.egg-info
python setup.py sdist
twine upload dist/*
```
