#!/usr/bin/env python3

"""
  Copyright 2019 Sebastian Bauer

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""

# requires packages:
# pycryptodomex
# tqdm
# pywin32 on windows
# argon2-cffi
# scrypt; only required if Python < 3.7; see https://bitbucket.org/mhallin/py-scrypt/src/default/README.rst for instructions

import base64
import os
import sys
import json
import configparser
import tqdm
import argparse
import re
import logging
import subprocess
import shlex
from typing import Dict, List, Tuple

import argon2
import hashlib
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode

if sys.platform == "win32":
    import win32file
    import pywintypes


def isAtMostPython36():
    return sys.version_info < (3, 7)


if isAtMostPython36():
    import scrypt

OUTPUT_SCRAMBLE = "scrambled"
MAPPING_FILE = "mapping.json"
CONFIG = "scramble.ini"
HEADER = "SCRAMBLE v1.1"

SCRAMBLE = "scramble"
UNSCRAMBLE = "unscramble"
DECRYPT = "decrypt"
CHANGE_PASSWORD = "passwd"


class FileScramble:
    def __init__(self, input_dir: str, output_dir: str, config_path: str = None):
        config = configparser.ConfigParser()

        self._configPath = os.path.join(os.getcwd(), CONFIG)
        if config_path:
            self._configPath = config_path
        if not os.path.exists(self._configPath):
            raise RuntimeError(f"No config file found at {self._configPath}")
        config.read(self._configPath)

        # General
        if input_dir:
            self._inputDir = input_dir
        else:
            self._inputDir = config.get("General", "Input", raw=True)
        if output_dir:
            self._outputDir = output_dir
        else:
            self._outputDir = config.get("General", "Output", raw=True)
        self._useSalt = False
        if config.getboolean("General", "Use salt"):
            self._useSalt = True
        self._storeCopyOfMapping = False
        if config.getboolean("General", "Store copy of mapping"):
            self._storeCopyOfMapping = True

        # External Program
        self._external_program = False
        if config.getboolean("External Program", "Launch program"):
            self._external_program = True
        self._external_program_path = config.get("External Program", "Program", raw=True)
        self._external_program_params = shlex.split(config.get("External Program", "Parameters", raw=True))
        try:
            self._external_program_timeout = config.getint("External Program", "Timeout")
        except ValueError:
            self._external_program_timeout = 0

        # Logging
        if config.getboolean("Logging", "Enable"):
            logging.basicConfig(filename=config.get("Logging", "File"), filemode="a+", level=config.get("Logging", "Level"),
                                format="%(asctime)s %(module)s %(levelname)s: %(message)s")
        self.debug = False
        if config.get("Logging", "Level").lower() == "debug":
            self.debug = True

        # encryption
        self._password = config.get("Encryption", "Password", raw=True)
        self._memory_cost = config.getint("Encryption", "Memory Cost")
        self._time_cost = config.getint("Encryption", "Time Cost")
        self._parallelism = config.getint("Encryption", "Parallelism")

    def get_scramble_output_directory(self) -> str:
        return os.path.join(self._outputDir, OUTPUT_SCRAMBLE)

    def get_scramble_input_directory(self) -> str:
        return os.path.join(self._inputDir, OUTPUT_SCRAMBLE)

    @staticmethod
    def _change_timestamps(source: str, destination: str):
        stats = os.stat(source)
        os.utime(destination, (stats.st_atime, stats.st_mtime))

        if sys.platform == "win32":
            handle = win32file.CreateFile(
                destination,  # file path
                win32file.GENERIC_WRITE,  # must opened with GENERIC_WRITE access
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                0
            )
            PyTime = pywintypes.Time(int(stats.st_ctime))
            win32file.SetFileTime(
                handle,
                PyTime
            )

    @staticmethod
    def generate_scrypt_hash(password: bytes, salt: bytes, bufferLengnth: int = 16) -> bytes:
        if isAtMostPython36():
            return scrypt.hash(password, salt, buflen=bufferLengnth)
        else:
            return hashlib.scrypt(password, salt=salt, n=1 << 14, r=8, p=1, dklen=bufferLengnth)

    def _read_mapping_file_v1_0(self, directory: str) -> Dict[str, Dict[str, str]]:
        """
        Deprecated. Use read_mapping_file_v1_1 instead
        :param directory:
        :return:
        """
        mapping = dict()
        if os.path.exists(os.path.join(directory, MAPPING_FILE)):
            try:
                with open(os.path.join(directory, MAPPING_FILE), "r") as mappingFile:
                    b64 = json.load(mappingFile)
                json_k = ["salt", "nonce", "header", "ciphertext", "tag"]
                jv = {k: b64decode(b64[k]) for k in json_k}
                self._salt = jv["salt"]
                key = self.generate_scrypt_hash(self._password.encode("utf-8"), self._salt)
                cipher = AES.new(key, AES.MODE_CCM, nonce=jv["nonce"])
                cipher.update(jv["header"])
                mapping = json.loads(cipher.decrypt_and_verify(jv["ciphertext"], jv["tag"]))
            except (ValueError, KeyError):
                print("Incorrect decryption")
                sys.exit(2)
        return mapping

    def _read_mapping_file_v1_1(self, directory: str) -> Dict[str, Dict[str, str]]:
        mapping = dict()
        if os.path.exists(os.path.join(directory, MAPPING_FILE)):
            try:
                with open(os.path.join(directory, MAPPING_FILE), "r") as mappingFile:
                    b64 = json.load(mappingFile)
                json_k = ["a2_params", "nonce", "header", "ciphertext", "tag"]
                jv = {k: b64decode(b64[k]) for k in json_k}
                a2_params = json.loads(jv["a2_params"])
                key = argon2.low_level.hash_secret_raw(
                    secret=self._password.encode("utf-8"),
                    version=a2_params["version"],
                    memory_cost=a2_params["memory_cost"],
                    time_cost=a2_params["time_cost"],
                    parallelism=a2_params["parallelism"],
                    type=argon2.Type.ID,
                    hash_len=a2_params["hash_len"],
                    salt=base64.b64decode(a2_params["salt"])
                )
                cipher = AES.new(key, AES.MODE_CCM, nonce=jv["nonce"])
                cipher.update(jv["header"])
                mapping = json.loads(cipher.decrypt_and_verify(jv["ciphertext"], jv["tag"]))
            except (ValueError, KeyError):
                print("Trying encryption for version 1.0")
                return self._read_mapping_file_v1_0(directory)
        return mapping

    def _write_mapping_file(self, mapping: Dict[str, Dict[str, str]]):
        salt = os.urandom(16)
        key = argon2.low_level.hash_secret_raw(
            secret=self._password.encode("utf-8"),
            memory_cost=self._memory_cost,
            time_cost=self._time_cost,
            parallelism=self._parallelism,
            type=argon2.Type.ID,
            hash_len=32,
            salt=salt
        )
        a2_params_json = json.dumps({
            "version": argon2.low_level.ARGON2_VERSION,
            "hash_len": 32,
            "time_cost": self._time_cost,
            "memory_cost": self._memory_cost,
            "parallelism": self._parallelism,
            "salt": base64.b64encode(salt).decode()
        })
        cipher = AES.new(key, AES.MODE_CCM)
        cipher.update(HEADER.encode("utf-8"))
        ciphertext, tag = cipher.encrypt_and_digest(bytes(json.dumps(mapping), "utf-8"))
        json_k = ["a2_params", "nonce", "header", "ciphertext", "tag"]
        json_v = [b64encode(x).decode("utf-8") for x in [a2_params_json.encode("utf-8"),
                                                         cipher.nonce, HEADER.encode("utf-8"), ciphertext, tag]]
        with open(os.path.join(self._outputDir, MAPPING_FILE), "w+") as mappingFile:
            json.dump(dict(zip(json_k, json_v)), mappingFile, indent=0)
        if self._storeCopyOfMapping:
            with open(os.path.join(os.path.dirname(os.path.abspath(self._configPath)), MAPPING_FILE), "w+") as mappingFile:
                json.dump(mapping, mappingFile, indent=2)

    def _copy_files(self, files: List[Tuple[str, str]], totalsize: int = 0, blocksize: int = 16 * 1024):
        # files is a list of tuples (src, dst) as absolute path
        # Partially taken from https://github.com/tqdm/tqdm/wiki/How-to-make-a-great-Progress-Bar
        # Preprocess the total files sizes
        size_counter = totalsize
        if size_counter <= 0:
            for src, _ in files:
                size_counter += os.stat(src).st_size

        # Load tqdm with size counter instead of file counter
        try:
            pbar = tqdm.tqdm(total=size_counter, unit='B', unit_scale=True, unit_divisor=1024)
        except AttributeError as ignore:
            pbar = None

        for src, dst in files:
            with open(src, "rb") as fsrc:
                if not os.path.exists(os.path.dirname(dst)):
                    try:
                        os.makedirs(os.path.dirname(dst))
                    except OSError as e:
                        if e.errno != e.EEXIST:
                            raise

                with open(dst, "wb") as fdst:
                    buf = 1
                    while buf:
                        buf = fsrc.read(blocksize)
                        fdst.write(buf)
                        if buf and pbar:
                            pbar.update(len(buf))
            self._change_timestamps(src, dst)

    def create_directory(self, directory: str):
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
            except OSError as e:
                if e.errno != e.EEXIST:
                    logging.error("Failed to create " + os.path.dirname(directory), exc_info=self.debug)
                    raise

    def scramble(self, verbose: bool = False, regex: str = None):
        self.create_directory(self.get_scramble_output_directory())

        pattern = None
        if regex:
            pattern = re.compile(regex)

        scrambled_mapping = self._read_mapping_file_v1_1(self._outputDir)
        reverse_scrambled_mapping = dict()
        for k, v in scrambled_mapping.items():
            reverse_scrambled_mapping.setdefault(v["file"], {"hash": k, "salt": v["salt"]})
        clear_text_mapping = dict()
        files_to_copy = list()

        # scan input directory, generate hashes and copy new files
        total_size_to_copy = 0
        for root, dirs, files in os.walk(self._inputDir, topdown=False):
            for name in files:
                relative_path = os.path.relpath(os.path.join(root, name), self._inputDir)

                if pattern:
                    if not pattern.search(relative_path):
                        continue
                    elif verbose:
                        print("Scrambling match: " + relative_path)
                    logging.debug("Scrambling match: " + relative_path)

                salt = b""
                if self._useSalt:
                    if relative_path in reverse_scrambled_mapping:
                        salt = b64decode(reverse_scrambled_mapping[relative_path]["salt"])

                if self._useSalt and salt == b"":
                    salt = os.urandom(16)

                hexdigest = hashlib.sha256(bytes(relative_path, "utf-8") + salt).hexdigest()

                clear_text_file = os.path.join(root, name)
                scrambled_file = os.path.join(self.get_scramble_output_directory(), hexdigest)

                skip_copy = False
                if relative_path in reverse_scrambled_mapping \
                        and hexdigest != reverse_scrambled_mapping.get(relative_path)["hash"]:
                    # salt turned off or on
                    file_to_rename = os.path.join(self.get_scramble_output_directory(),
                                                  reverse_scrambled_mapping.get(relative_path)["hash"])
                    if os.path.exists(file_to_rename):
                        os.rename(file_to_rename, scrambled_file)
                        text = "Renamed {old} to {new}".format(old=file_to_rename, new=scrambled_file)
                        logging.debug(text)
                        if verbose:
                            print(text)
                        skip_copy = True

                # add files to mapping
                if hexdigest in clear_text_mapping:
                    collision = clear_text_mapping.get(hexdigest)
                    if self._useSalt:
                        while hexdigest in clear_text_mapping:
                            salt = os.urandom(16)
                            hexdigest = hashlib.sha256(bytes(relative_path, "utf-8") + salt).hexdigest()
                        clear_text_mapping.setdefault(hexdigest, {"file": relative_path,
                                                                  "salt": b64encode(salt).decode("utf-8")})
                        scrambled_file = os.path.join(self.get_scramble_output_directory(), hexdigest)
                        print(hexdigest)
                    else:
                        print("sha256 collision! Use salted hashes to prevent this from happening {collisionFile} "
                              "generates same value as {file}: {hash}"
                              .format(collisionFile=collision, file=relative_path, hash=hexdigest))
                else:
                    clear_text_mapping.setdefault(hexdigest, {"file": relative_path,
                                                              "salt": b64encode(salt).decode("utf-8")})

                if not skip_copy and hexdigest not in scrambled_mapping:
                    # copy files that are not present
                    files_to_copy.append((clear_text_file, scrambled_file))
                    total_size_to_copy += os.stat(clear_text_file).st_size
                else:
                    # check if files are the same size and have the same modification time
                    scrambledFileStats = os.stat(scrambled_file)
                    clearTextFileStats = os.stat(clear_text_file)
                    if hexdigest in scrambled_mapping and (not clearTextFileStats
                                                          or (scrambledFileStats.st_size != clearTextFileStats.st_size)
                                                          or (scrambledFileStats.st_mtime != clearTextFileStats.st_mtime)):
                        files_to_copy.append((clear_text_file, scrambled_file))

        # remove deleted files
        files_removed = 0
        files_skipped = 0
        for k in scrambled_mapping.keys():
            if k not in clear_text_mapping:
                file_to_remove = os.path.join(self.get_scramble_output_directory(), k)
                if os.path.exists(file_to_remove):
                    logging.debug("removing " + k)
                    if verbose:
                        print("removing " + k)
                    os.remove(file_to_remove)
                    files_removed += 1
            else:
                files_skipped += 1

        if len(files_to_copy) > 0:
            self._copy_files(files_to_copy)
        logging.info(f"Copied and scrambled {len(files_to_copy)}, removed {files_removed}, "
                     f"and skipped {files_skipped} files.")
        if verbose:
            print(f"Copied and scrambled {len(files_to_copy)}, removed {files_removed}, "
                  f"and skipped {files_skipped} files.")
        self._write_mapping_file(clear_text_mapping)

    def clean(self, mode: str):
        mapping = dict()
        if mode == SCRAMBLE:
            mapping = self._read_mapping_file_v1_1(self._outputDir)
        elif mode == UNSCRAMBLE:
            mapping = self._read_mapping_file_v1_1(self._inputDir)

        if len(mapping.keys()) == 0:
            print("No mapping file. Skipping cleaning")
            return

        # scan for files not present in mapping file
        for root, dirs, files in os.walk(self.get_scramble_output_directory(), topdown=False):
            for name in files:
                if name not in mapping:
                    os.remove(os.path.join(self.get_scramble_output_directory(), name))

    def unscramble(self, verbose: bool = False, regex: str = None):
        mapping = self._read_mapping_file_v1_1(self._inputDir)
        if len(mapping.keys()) == 0:
            print("No mapping file. Can't continue.")
            sys.exit(2)

        self.create_directory(self._outputDir)

        pattern = None
        if regex:
            pattern = re.compile(regex)

        files_to_copy = list()
        total_size = 0
        for hashedName, clearNameDict in mapping.items():
            clear_name = clearNameDict["file"]

            if pattern:
                if not pattern.search(clear_name):
                    continue
                elif verbose:
                    print("Unscrambling match: " + clear_name)
            logging.debug("Unscrambling match: " + clear_name)

            hashed_file = os.path.join(self.get_scramble_input_directory(), hashedName)
            if not os.path.exists(hashed_file):
                print("File {hash} || {file} is missing".format(hash=hashedName, file=clear_name))
            else:
                total_size += os.stat(hashed_file).st_size
                files_to_copy.append((hashed_file, os.path.join(self._outputDir, clear_name)))

        if len(files_to_copy) > 0:
            self._copy_files(files_to_copy, total_size)

    def decrypt(self):
        mapping = self._read_mapping_file_v1_1(self._inputDir)
        if len(mapping.keys()) == 0:
            print("No mapping file. Can't continue.")
            sys.exit(2)

        self.create_directory(self._outputDir)
        with open(os.path.join(self._outputDir, MAPPING_FILE), "w+") as mappingFile:
            json.dump(mapping, mappingFile, indent=2)

    def launch_process(self):
        if self._external_program:
            try:
                timeout = None
                if self._external_program_timeout > 0:
                    timeout = self._external_program_timeout
                logging.info(f"Launching {self._external_program_path}")
                logging.debug(f"Parameters used: {self._external_program_params}")
                p = subprocess.run([self._external_program_path, *self._external_program_params],
                                   timeout=timeout, shell=False)
                if p.returncode:
                    logging.warning(f"External program returned error code {p.returncode}")
                else:
                    logging.info(f"External program finished without error")
            except subprocess.TimeoutExpired:
                logging.error(f"Timeout of {self._external_program_timeout} reached for external program",
                              exc_info=self.debug)
            except:
                logging.error("Failed to launch external program", exc_info=self.debug)

    def passwd(self):
        print("Please enter old password:")
        mapping = self._read_mapping_file_v1_1(self._inputDir)

        print("Please enter new password:")
        self._password = bytes(input(), "utf-8")
        self._outputDir = self._inputDir
        self._write_mapping_file(mapping)
        print("Password changed. Please update your config file.")


def main():
    parser = argparse.ArgumentParser(description="""
    Copy files from input to output directory and scramble file names.
    When no input or output directory is specified, the respective one provided in the configuration file will be used. 
    Files are being overwritten without any warning!
    """)

    parser.add_argument("mode", choices=[SCRAMBLE, UNSCRAMBLE, DECRYPT, CHANGE_PASSWORD],
                        help=f""""{SCRAMBLE}" will scramble the file names; "{UNSCRAMBLE}" will unscramble the file names; 
                        "{DECRYPT}" will only decrypt the mapping file; {CHANGE_PASSWORD} will change the password that is used to encrypt the mapping file (don't forget to update your config!).""")
    parser.add_argument("--clean", dest="clean", action="store_true", default=False,
                        help="Scan scrambled directory for files that should not be there")
    parser.add_argument("--config", dest="config",
                        help="Specify path of the config file. If not specified, the current working dir will be used.")
    parser.add_argument("--verbose", dest="verbose", action="store_true", default=False)
    parser.add_argument("--regex", dest="regex",
                        help="Add a regex to scramble or unscramble only the relative paths that match the expression. "
                             "This will use Python regex syntax and call re.search(). "
                             "See https://docs.python.org/3/library/re.html for more information.")
    group = parser.add_argument_group("Directories")
    group.add_argument("-i", dest="input", help="Input directory")
    group.add_argument("-o", dest="output", help="Output directory")

    results = parser.parse_args()

    scrambler = None
    try:
        scrambler = FileScramble(results.input, results.output, results.config)
        if results.clean:
            scrambler.clean(results.mode)
        if results.mode == SCRAMBLE:
            scrambler.scramble(verbose=results.verbose, regex=results.regex)
            scrambler.launch_process()
        if results.mode == UNSCRAMBLE:
            if results.input == "None" or results.output == "None":
                print("Input and output must be specified when using unscramble.")
            else:
                scrambler.unscramble(verbose=results.verbose, regex=results.regex)
        if results.mode == DECRYPT:
            if results.input == "None" or results.output == "None":
                print("Input and output must be specified when using decrypt.")
            else:
                print("Please enter the password: ")
                scrambler._password = bytes(input(), "utf-8")
                scrambler.decrypt()
        if results.mode == CHANGE_PASSWORD:
            if results.input == "None":
                print("Please specify where the mapping file is located using '-i <path>'")
            else:
                scrambler.passwd()

    except Exception as e:
        if scrambler:
            logging.error("Unexpected error occurred.", exc_info=scrambler.debug)
        else:
            print("Unexpected error occurred.")
        raise


if __name__ == "__main__":
    main()
