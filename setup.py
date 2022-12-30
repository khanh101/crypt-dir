import setuptools

if __name__ == "__main__":
    with open("README.md") as f:
        long_description = f.read()

    setuptools.setup(
        name="crypt-dir",
        version="0.1.2",
        author="Nguyen Ngoc Khanh",
        author_email="khanh.nguyen.contact@gmail.com",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/khanh-nguyen-code/crypt-dir",
        packages=setuptools.find_packages(),
    )
