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
        if inputDir:
            self._inputDir = inputDir
        else:
            self._inputDir = config["General"]["Input"]
        if outputDir:
            self._outputDir = outputDir
        else:
            self._outputDir = config["General"]["Output"]
        self._useSalt = False
        if str(config["General"]["UseSalt"]).lower() == "yes":
            self._useSalt = True
        self._storeCopyOfMapping = False
        if str(config["General"]["StoreCopyOfMapping"]).lower() == "yes":
            self._storeCopyOfMapping = True
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
        json_v = [b64encode(x).decode("utf-8") for x in [self._salt, cipher.nonce, HEADER.encode("utf-8"), ciphertext, tag]]
        with open(os.path.join(self._outputDir, MAPPING_FILE), "w+") as mappingFile:
            json.dump(dict(zip(json_k, json_v)), mappingFile, indent=0)
        with open(os.path.join(os.getcwd(), MAPPING_FILE), "w+") as mappingFile:
            json.dump(mapping, mappingFile, indent=0)

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

    def scramble(self, verbose=False):
        scrambledMapping = self._readMappingFile(self._outputDir)
        reverseScrambledMapping = dict()
        for k, v in scrambledMapping.items():
            reverseScrambledMapping.setdefault(v["file"], {"hash": k, "salt": v["salt"]})
        clearTextMapping = dict()
        filesToCopy = list()

        # scan input directory, generate hashes and copy new files
        totalSizeToCopy = 0
        for root, dirs, files in os.walk(self._inputDir, topdown=False):
            for name in files:
                relativePath = os.path.relpath(os.path.join(root, name), self._inputDir)

                salt = b""
                if self._useSalt:
                    if relativePath in reverseScrambledMapping:
                        salt = b64decode(reverseScrambledMapping[relativePath]["salt"])

                if self._useSalt and salt == b"":
                    salt = get_random_bytes(16)

                hexdigest = hashlib.sha256(bytes(relativePath, "utf-8") + salt).hexdigest()

                clearTextFile = os.path.join(root, name)
                scrambledFile = os.path.join(self.getScrambleOutputDirectory(), hexdigest)

                skipCopy = False
                if relativePath in reverseScrambledMapping and hexdigest != reverseScrambledMapping.get(relativePath)["hash"]:
                    # salt turned off or on
                    fileToRename = os.path.join(self.getScrambleOutputDirectory(), reverseScrambledMapping.get(relativePath)["hash"])
                    if os.path.exists(fileToRename):
                        os.rename(fileToRename, scrambledFile)
                        if verbose:
                            print("Renamed {old} to {new}".format(old=fileToRename, new=scrambledFile))
                        skipCopy = True

                if not skipCopy and hexdigest not in scrambledMapping:
                    # copy files that are not present
                    filesToCopy.append((clearTextFile, scrambledFile))
                    totalSizeToCopy += os.stat(clearTextFile).st_size
                else:
                    # check if files are the same size and have the same modification time
                    scrambledFileStats = os.stat(scrambledFile)
                    clearTextFileStats = os.stat(clearTextFile)
                    if hexdigest in scrambledMapping and (not clearTextFileStats
                                                          or (scrambledFileStats.st_size != clearTextFileStats.st_size)
                                                          or (scrambledFileStats.st_mtime != clearTextFileStats.st_mtime)):
                        filesToCopy.append((clearTextFile, scrambledFile))

                # add files to mapping
                if hexdigest in clearTextMapping:
                    # TODO add log in case of collision
                    # TODO add random salt to prevent collisions
                    collision = clearTextMapping.get(hexdigest)
                    print("sha256 collision! {collisionFile} generates same value as {file}: {hash}".format(collisionFile=collision, file=relativePath, hash=hexdigest))
                else:
                    clearTextMapping.setdefault(hexdigest, {"file": relativePath, "salt": b64encode(salt).decode("utf-8")})

        # remove deleted files
        for k in scrambledMapping.keys():
            if k not in clearTextMapping:
                fileToRemove = os.path.join(self.getScrambleOutputDirectory(), k)
                if os.path.exists(fileToRemove):
                    if verbose:
                        print("removing " + k)
                    os.remove(fileToRemove)

        if len(filesToCopy) > 0:
            self._copyFiles(filesToCopy)
        self._writeMappingFile(clearTextMapping)

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
        for hashedName, clearNameDict in mapping.items():
            clearName = clearNameDict["file"]
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
    parser.add_argument("--verbose", dest="verbose", action="store_true", default=False)
    group = parser.add_argument_group("Directories")
    group.add_argument("-i", dest="input", help="Input directory")
    group.add_argument("-o", dest="output", help="Output directory")

    results = parser.parse_args()

    scrambler = FileScramble(results.input, results.output)
    if results.clean:
        scrambler.clean(results.mode)
    if results.mode == SCRAMBLE:
        scrambler.scramble(results.verbose)
    if results.mode == UNSCRAMBLE:
        if results.input == "None" or results.output == "None":
            print("Input and output must be specified when using unscramble.")
        else:
            scrambler.unscramble()


if __name__ == "__main__":
    main()
