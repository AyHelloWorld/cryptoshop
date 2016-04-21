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

import botan
from .nonce import generate_nonce_timestamp

nonce_length = 21


def encrypt_string(string, masterkey, header, bool_encry):
    engine1 = botan.cipher(algo="Serpent/GCM", encrypt=bool_encry)
    engine2 = botan.cipher(algo="AES-256/GCM", encrypt=bool_encry)
    engine3 = botan.cipher(algo="Twofish/GCM", encrypt=bool_encry)

    hash1 = botan.hash_function(algo="SHA-256")
    hash1.update(masterkey)
    hashed1 = hash1.final()

    hash2 = botan.hash_function(algo="SHA-256")
    hash2.update(hashed1)
    hashed2 = hash2.final()

    engine1.set_key(key=masterkey)
    engine1.set_assoc_data(header)

    engine2.set_key(key=hashed1)
    engine2.set_assoc_data(header)

    engine3.set_key(key=hashed2)
    engine3.set_assoc_data(header)

    if bool_encry is True:
        nonce1 = generate_nonce_timestamp()
        nonce2 = generate_nonce_timestamp()
        nonce3 = generate_nonce_timestamp()

        engine1.start(nonce=nonce1)
        engine2.start(nonce=nonce2)
        engine3.start(nonce=nonce3)

        encrypted1 = engine1.finish(string)
        encrypted2 = engine2.finish(encrypted1)
        encrypted3 = engine3.finish(encrypted2)
        return nonce1 + nonce2 + nonce3 + encrypted3
    else:
        nonce1 = string[:nonce_length]
        nonce2 = string[nonce_length:nonce_length * 2]
        nonce3 = string[nonce_length * 2:nonce_length * 3]
        encryptedstring = string[nonce_length * 3:]

        engine1.start(nonce=nonce1)
        engine2.start(nonce=nonce2)
        engine3.start(nonce=nonce3)

        decryptedstring1 = engine3.finish(encryptedstring)
        if decryptedstring1 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        decryptedstring2 = engine2.finish(decryptedstring1)
        if decryptedstring2 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        decryptedstring3 = engine1.finish(decryptedstring2)
        if decryptedstring3 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        else:
            return decryptedstring3
