# Filename-Scramble
Scramble file names and store names in an encrypted file.

## Setup
Requires Python 3, tested on Python 3.6
Be sure the following Python modules are installed:
```
pycryptodomex
tqdm
pywin32 on windows
scrypt
```
See [scrypt readme](https://bitbucket.org/mhallin/py-scrypt/src/default/README.rst) for installation instructions.

## Usage
```
usage: scramble.py [-h] [--clean] [--verbose] [-i INPUT] [-o OUTPUT]
                   {scramble,unscramble}

Copy files from input to output directory and scramble file names. When no
input or output directory is specified, the respective one provided in the
configuration file will be used. Files are being overwritten without any
warning!

positional arguments:
  {scramble,unscramble}

optional arguments:
  -h, --help            show this help message and exit
  --clean               Scan output directory for files that should not be
                        there
  --verbose

Directories:
  -i INPUT              Input directory
  -o OUTPUT             Output directory
  ```
