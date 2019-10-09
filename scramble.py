#!/usr/bin/env python3

"""
  Copyright 2017 Sebastian Bauer

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

import os
import hashlib
from Cryptodome.Cipher import AES
from base64 import b64encode
import json
import configparser
import tqdm
from shutil import copyfile

import platform
if platform.system() == "Windows":
    import win32file
    import pywintypes

OUTPUT_SCRAMBLE = "scrambled"
MAPPING_FILE = "mapping.json"
CONFIG = "scramble.ini"


class FileScramble:
    def __init__(self):
        self._mapping = dict()

        config = configparser.ConfigParser()
        config.read(CONFIG)
        self._inputDir = config["Folders"]["Input"]
        self._outputDir = config["Folders"]["Output"]

        if not os.path.exists(os.path.join(self._outputDir, OUTPUT_SCRAMBLE)):
            try:
                os.makedirs(os.path.join(self._outputDir, OUTPUT_SCRAMBLE))
            except OSError:
                # TODO
                print("Couldn't create output folder")

    def changeTimestamps(self, source, destination):
        stats = os.stat(source)
        os.utime(destination, (stats.st_atime, stats.st_mtime))

        if platform.system() == "Windows":
            handle = win32file.CreateFile(
                destination,  # file path
                win32file.GENERIC_WRITE,  # must opened with GENERIC_WRITE access
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                0
            )
            PyTime = pywintypes.Time(stats.st_ctime)
            win32file.SetFileTime(
                handle,
                PyTime
            )

    def scramble(self):
        oldMapping = dict()
        filesToCopy = list()

        if os.path.exists(os.path.join(self._outputDir, MAPPING_FILE)):
            with open(os.path.join(self._outputDir, MAPPING_FILE), "r") as mappingFile:
                oldMapping = json.load(mappingFile)

        for root, dirs, files in os.walk(self._inputDir, topdown=False):
            for name in files:
                relativePath = os.path.relpath(os.path.join(root, name), self._inputDir)
                hexdigest = hashlib.sha256(bytes(relativePath, "utf-8")).hexdigest()

                newFile = os.path.join(root, name)
                oldFile = os.path.join(self._outputDir, OUTPUT_SCRAMBLE, hexdigest)

                if hexdigest not in oldMapping:
                    # copy files that are not present
                    filesToCopy.append((newFile, oldFile))
                else:
                    # check if files are the same size and have the same modification time
                    newFileStats = os.stat(newFile)
                    try:
                        oldFileStats = None
                        oldFileStats = os.stat(oldFile)
                    except FileNotFoundError:
                        pass  # nothing to do here
                    finally:
                        if not oldFileStats or (newFileStats.st_size != oldFileStats.st_size) or (newFileStats.st_mtime != oldFileStats.st_mtime):
                            filesToCopy.append((newFile, oldFile))

                # add files to mapping
                self._mapping.setdefault(hexdigest, relativePath)
                # TODO add log in case of collision

        # TODO removal list

        for src, dst in tqdm.tqdm(filesToCopy, unit=" file"):
            copyfile(src, dst)
            self.changeTimestamps(src, dst)


        with open(os.path.join(self._outputDir, MAPPING_FILE), "w+") as mappingFile:
            json.dump(self._mapping, mappingFile, indent=0)


        """
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(b"test")
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'nonce': nonce, 'ciphertext': ct})
        print(result)
        """


def main():
    scrambler = FileScramble()
    scrambler.scramble()


if __name__ == "__main__":
    main()
