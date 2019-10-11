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
# scrypt; see https://bitbucket.org/mhallin/py-scrypt/src/default/README.rst for instructions

import os
import sys
import json
import configparser
import tqdm
import argparse

import hashlib
import scrypt
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode

import platform
if platform.system() == "Windows":
    import win32file
    import pywintypes

OUTPUT_SCRAMBLE = "scrambled"
MAPPING_FILE = "mapping.json"
CONFIG = "scramble.ini"
HEADER = "SCRAMBLE v1"

SCRAMBLE = "scramble"
UNSCRAMBLE = "unscramble"


class FileScramble:
    def __init__(self, inputDir, outputDir):
        config = configparser.ConfigParser()
        config.read(CONFIG)
        if inputDir != "None":
            self._inputDir = inputDir
        else:
            self._inputDir = config["Directories"]["Input"]
        if outputDir != "None":
            self._outputDir = outputDir
        else:
            self._outputDir = config["Directories"]["Output"]
        self._password = config["Encryption"]["Password"]
        self._salt = None

        if not os.path.exists(self.getScrambleOutputDirectory()):
            try:
                os.makedirs(self.getScrambleOutputDirectory())
            except OSError:
                # TODO
                print("Couldn't create output directory")

    def getScrambleOutputDirectory(self):
        return os.path.join(self._outputDir, OUTPUT_SCRAMBLE)

    def getScrambleInputDirectory(self):
        return os.path.join(self._inputDir, OUTPUT_SCRAMBLE)

    @staticmethod
    def _changeTimestamps(source, destination):
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

    def _readMappingFile(self, directory):
        mapping = dict()
        if os.path.exists(os.path.join(directory, MAPPING_FILE)):
            try:
                with open(os.path.join(directory, MAPPING_FILE), "r") as mappingFile:
                    b64 = json.load(mappingFile)
                json_k = ["salt", "nonce", "header", "ciphertext", "tag"]
                jv = {k: b64decode(b64[k]) for k in json_k}
                self._salt = jv["salt"]
                key = scrypt.hash(self._password, self._salt, buflen=16)
                cipher = AES.new(key, AES.MODE_CCM, nonce=jv['nonce'])
                cipher.update(jv['header'])
                mapping = json.loads(cipher.decrypt_and_verify(jv['ciphertext'], jv['tag']))
            except (ValueError, KeyError):
                print("Incorrect decryption")
                sys.exit(2)
        return mapping

    def _writeMappingFile(self, mapping):
        if not self._salt:
            self._salt = get_random_bytes(16)
        key = scrypt.hash(self._password, self._salt, buflen=16)
        cipher = AES.new(key, AES.MODE_CCM)
        cipher.update(HEADER.encode("utf-8"))
        ciphertext, tag = cipher.encrypt_and_digest(bytes(json.dumps(mapping), "utf-8"))
        json_k = ["salt", "nonce", "header", "ciphertext", "tag"]
        json_v = [b64encode(x).decode('utf-8') for x in [self._salt, cipher.nonce, HEADER.encode("utf-8"), ciphertext, tag]]
        with open(os.path.join(self._outputDir, MAPPING_FILE), "w+") as mappingFile:
            json.dump(dict(zip(json_k, json_v)), mappingFile, indent=0)

    def _copyFiles(self, files, totalsize=0, blocksize=16 * 1024):
        # files is a list of tuples (src, dst) as absolute path
        # Partially taken from https://github.com/tqdm/tqdm/wiki/How-to-make-a-great-Progress-Bar
        # Preprocess the total files sizes
        sizecounter = totalsize
        if sizecounter <= 0:
            for src, _ in files:
                sizecounter += os.stat(src).st_size

        # Load tqdm with size counter instead of file counter
        with tqdm.tqdm(total=sizecounter, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
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
                            if buf:
                                pbar.update(len(buf))
                self._changeTimestamps(src, dst)

    def scramble(self):
        oldMapping = self._readMappingFile(self._outputDir)
        newMapping = dict()
        filesToCopy = list()

        # scan input directory, generate hashes and copy new files
        totalSizeToCopy = 0
        for root, dirs, files in os.walk(self._inputDir, topdown=False):
            for name in files:
                relativePath = os.path.relpath(os.path.join(root, name), self._inputDir)
                hexdigest = hashlib.sha256(bytes(relativePath, "utf-8")).hexdigest()

                newFile = os.path.join(root, name)
                oldFile = os.path.join(self.getScrambleOutputDirectory(), hexdigest)

                oldFileStats = None
                if hexdigest not in oldMapping:
                    # copy files that are not present
                    filesToCopy.append((newFile, oldFile))
                    totalSizeToCopy += os.stat(newFile).st_size
                elif os.path.exists(newFile) and os.path.isfile(newFile):
                    # check if files are the same size and have the same modification time
                    newFileStats = os.stat(newFile)
                    oldFileStats = os.stat(oldFile)
                if hexdigest in oldMapping and (not oldFileStats or (newFileStats.st_size != oldFileStats.st_size) or (newFileStats.st_mtime != oldFileStats.st_mtime)):
                    filesToCopy.append((newFile, oldFile))

                # add files to mapping
                if hexdigest in newMapping:
                    # TODO add log in case of collision
                    # TODO add random salt to prevent collisions
                    collision = newMapping.get(hexdigest)
                    print("sha256 collision! {collisionFile} generates same value as {file}: {hash}".format(collisionFile=collision, file=relativePath, hash=hexdigest))
                else:
                    newMapping.setdefault(hexdigest, relativePath)

        # remove deleted files
        for k in oldMapping.keys():
            if k not in newMapping:
                print("removing " + k)
                os.remove(os.path.join(self.getScrambleOutputDirectory(), k))

        if len(filesToCopy) > 0:
            self._copyFiles(filesToCopy)
        self._writeMappingFile(newMapping)

    def clean(self, mode):
        mapping = dict()
        if mode == SCRAMBLE:
            mapping = self._readMappingFile(self._outputDir)
        elif mode == UNSCRAMBLE:
            mapping = self._readMappingFile(self._inputDir)

        if len(mapping.keys()) == 0:
            print("No mapping file. Skipping cleaning")
            return

        # scan for files not present in mapping file
        for root, dirs, files in os.walk(self.getScrambleOutputDirectory(), topdown=False):
            for name in files:
                if name not in mapping:
                    os.remove(os.path.join(self.getScrambleOutputDirectory(), name))

    def unscramble(self):
        mapping = self._readMappingFile(self._inputDir)
        if len(mapping.keys()) == 0:
            print("No mapping file. Can't continue.")
            sys.exit(2)

        if not os.path.exists(self._outputDir):
            try:
                os.makedirs(self._outputDir)
            except OSError as e:
                if e.errno != e.EEXIST:
                    raise

        filesToCopy = list()
        totalSize = 0
        for hashedName, clearName in mapping.items():
            hashedFile = os.path.join(self.getScrambleInputDirectory(), hashedName)
            if not os.path.exists(hashedFile):
                print("File {hash} || {file} is missing".format(hash=hashedName, file=clearName))
            else:
                totalSize += os.stat(hashedFile).st_size
                filesToCopy.append((hashedFile, os.path.join(self._outputDir, clearName)))

        if len(filesToCopy) > 0:
            self._copyFiles(filesToCopy, totalSize)


def main():
    parser = argparse.ArgumentParser(description="""
    Copy files from input to output directory and scramble file names.
    When no input or output directory is specified, the respective one provided in the configuration file will be used. 
    Files are being overwritten without any warning!
    """)

    parser.add_argument("mode", choices=[SCRAMBLE, UNSCRAMBLE])
    parser.add_argument("--clean", dest="clean", action="store_true", default=False, help="Scan output directory for files that should not be there")
    group = parser.add_argument_group("Directories")
    group.add_argument("-i", dest="input", help="Input directory")
    group.add_argument("-o", dest="output", help="Output directory")

    results = parser.parse_args()

    scrambler = FileScramble(str(results.input), str(results.output))
    if results.clean:
        scrambler.clean(results.mode)
    if results.mode == SCRAMBLE:
        scrambler.scramble()
    if results.mode == UNSCRAMBLE:
        if results.input == "None" or results.output == "None":
            print("Input and output must be specified when using unscramble.")
        else:
            scrambler.unscramble()


if __name__ == "__main__":
    main()
