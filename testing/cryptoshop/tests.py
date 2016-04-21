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


from cryptoshop.nonce import generate_nonce_timestamp
from cryptoshop import encryptstring
from cryptoshop import decryptstring
from cryptoshop import encryptfile
from cryptoshop import decryptfile


import unittest


class MyTestCase(unittest.TestCase):
    @staticmethod
    def test_nonce_generating():
        x = 0
        while x < 100:
            generate_nonce_timestamp()
            x += 1

    @staticmethod
    def test_enc_dec_string():

        # encrypt
        cryptostring = encryptstring(string="my super secret text to encrypt", passphrase="my passphrase")

        # decrypt
        decryptstring(string=cryptostring, passphrase="my passphrase")

    @staticmethod
    def test_enc_dec_file():
        encryptfile(filename="encrypt.me", passphrase="my passphrase", algo="twf")
        decryptfile(filename="encrypt.me.cryptoshop", passphrase="my passphrase")


if __name__ == '__main__':
    unittest.main()
