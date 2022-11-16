# CRYPT_DIR

- Encrypt all your files in a directory and write into another directory
- Clean the encrypted directory if files or directories have been deleted

# INSTALLATION

```shell
pip install --upgrade crypt-dir
```

# UPLOAD

```shell
rm -rf dist crypt_dir.egg-info
python setup.py sdist
twine upload dist/*
```