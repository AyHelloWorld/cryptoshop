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


from cryptoshop import encryptstring
from cryptoshop import decryptstring
from cryptoshop import encryptfile
from cryptoshop import decryptfile
from cryptoshop._nonce_engine import generate_nonce_timestamp
from cryptoshop._derivation_engine import calc_derivation
from cryptoshop._derivation_engine import calc_derivation_formated


def test_derivation():
    print("============< test Argon2 derivation raw >============")
    print("passphrase= my password")
    print("salt= b'123456789'")
    test = calc_derivation(passphrase="my password", salt=b"123456789")
    print("hash= " + str(test))


def test_derivation2():
    print("============< test Argon2 derivation formated >============")
    print("passphrase= my password")
    print("salt= b'123456789'")
    test = calc_derivation_formated(passphrase="my password", salt=b"123456789")
    print("hash= " + str(test))


def test_nonce():
    print("============< test generating 100 uniques nonces  >============")
    i = 1
    while i < 100:
        print(generate_nonce_timestamp())
        i += 1


def test_enc_dec_string():
    # encrypt
    pt = "my super secret text to encrypt"
    cryptostring = encryptstring(string=pt, passphrase="my passphrase")

    # decrypt
    assert decryptstring(string=cryptostring, passphrase="my passphrase") == pt


def test_enc_dec_file():
    # encrypt
    encryptfile(filename="encrypt.me", passphrase="my passphrase", algo="srp")
    # decrypt
    result = decryptfile(filename="encrypt.me.cryptoshop", passphrase="my passphrase")
    assert (result == "successfully decrypted")
