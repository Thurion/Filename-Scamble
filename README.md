# Filename-Scramble
Scramble file names and store names in an encrypted file.

## Setup
Requires Python 3, tested on Python 3.6 and 3.7.
Be sure the following Python modules are installed:
```
pycryptodomex
tqdm
pywin32 on windows
scrypt (only needed when using Python < 3.7)
```
See [scrypt readme](https://bitbucket.org/mhallin/py-scrypt/src/default/README.rst) for installation instructions.

## Usage
```
usage: scramble.py [-h] [--clean] [--verbose] [--regex REGEX] [-i INPUT]
                   [-o OUTPUT]
                   {scramble,unscramble,decrypt}

Copy files from input to output directory and scramble file names. When no
input or output directory is specified, the respective one provided in the
configuration file will be used. Files are being overwritten without any
warning!

positional arguments:
  {scramble,unscramble,decrypt}
                        "scramble" will scramble the file names; "unscramble"
                        will unscramble the file names; "decrypt" will only
                        decrypt the mapping file.

optional arguments:
  -h, --help            show this help message and exit
  --clean               Scan scrambled directory for files that should not be
                        there
  --verbose
  --regex REGEX         Add a regex to scramble or unscramble only the
                        relative paths that match the expression. This will
                        use Python regex syntax and call re.search(). See
                        https://docs.python.org/3/library/re.html for more
                        information.

Directories:
  -i INPUT              Input directory
  -o OUTPUT             Output directory
  ```
