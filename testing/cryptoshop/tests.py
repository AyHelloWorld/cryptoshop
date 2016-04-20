#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Cryptoshop Strong file encryption.
# Encrypt and decrypt file in GCM mode with AES, Serpent or Twofish as secure as possible.
# Copyright(C) 2016 CORRAIRE Fabrice. antidote1911@gmail.com

# ############################################################################
# This file is part of Cryptoshop-GUI (full Qt5 gui for Cryptoshop).
#
#    Cryptoshop is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Cryptoshop is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Cryptoshop.  If not, see <http://www.gnu.org/licenses/>.
# ############################################################################

from cryptoshop import encryptfile
from cryptoshop import decryptfile
from cryptoshop.nonce import generate_nonce_timestamp
from cryptoshop.internalkey import encry_decry_internalkey
import unittest
import botan
import argon2


class MyTestCase(unittest.TestCase):
    @staticmethod
    def test_nonce():
        x = 0
        while x < 1000:
            generate_nonce_timestamp()
            x += 1

    @staticmethod
    def test_argon2():
        salt = botan.rng().get(256)
        argon2.low_level.hash_secret_raw((str.encode("my passphrase")), salt=salt, hash_len=32,
                                         time_cost=2000, memory_cost=1024,
                                         parallelism=8, type=argon2.low_level.Type.I)

    @staticmethod
    def test_encrypt():
        encryptfile(filename="encrypt.me", passphrase="my passphrase", algo="twf")

    @staticmethod
    def test_decrypt():
        decryptfile(filename="encrypt.me.cryptoshop", passphrase="my passphrase")

    @staticmethod
    def test_enc_dec_cascade():
        key = botan.rng().get(32)
        key2 = botan.rng().get(32)

        # encryption...
        encryptedkey = encry_decry_internalkey(assoc_data=b"my assoc data", internalkey=key, masterkey=key2,
                                               bool_encry=True)

        # decryption
        encry_decry_internalkey(assoc_data=b"my assoc data", internalkey=encryptedkey, masterkey=key2, bool_encry=False)


if __name__ == '__main__':
    unittest.main()
