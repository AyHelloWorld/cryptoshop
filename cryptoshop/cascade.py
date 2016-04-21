#!/usr/bin/env python
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

import sys

from .nonce import generate_nonce_timestamp

try:
    import botan
except ImportError:
    print("Please install the last version of Botan crypto library.")
    print("http://botan.randombit.net/#download")
    print("For Linux users, try to find it in your package manager.")
    sys.exit(0)

nonce_length = 21


def encry_decry_cascade(internalkey, masterkey, bool_encry, assoc_data):
    """
    When bool_encry is True, encrypt the internal key with master key. When it is False, the function extract the nonce
    from the encrypted key (first 21 bytes), and decrypt the internal key.
    :param internalkey: the internal key randomly generated in bytes to encrypt or decrypt.
    :param masterkey: a 32 bytes key in bytes.
    :param bool_encry: if bool_encry is True, chunk is encrypted. Else, it will be decrypted.
    :param assoc_data: Additional data added to GCM authentication.
    :return: if bool_encry is True, corresponding nonce + encryptedkey. Else, the decrypted internal key.
    """
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
    engine1.set_assoc_data(assoc_data)

    engine2.set_key(key=hashed1)
    engine2.set_assoc_data(assoc_data)

    engine3.set_key(key=hashed2)
    engine3.set_assoc_data(assoc_data)

    if bool_encry is True:
        nonce1 = generate_nonce_timestamp()
        nonce2 = generate_nonce_timestamp()
        nonce3 = generate_nonce_timestamp()

        engine1.start(nonce=nonce1)
        engine2.start(nonce=nonce2)
        engine3.start(nonce=nonce3)

        key1 = engine1.finish(internalkey)
        key2 = engine2.finish(key1)
        key3 = engine3.finish(key2)
        return nonce1 + nonce2 + nonce3 + key3
    else:
        nonce1 = internalkey[:nonce_length]
        nonce2 = internalkey[nonce_length:nonce_length * 2]
        nonce3 = internalkey[nonce_length * 2:nonce_length * 3]
        encryptedkey = internalkey[nonce_length * 3:]

        engine1.start(nonce=nonce1)
        engine2.start(nonce=nonce2)
        engine3.start(nonce=nonce3)

        decryptedkey1 = engine3.finish(encryptedkey)
        if decryptedkey1 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        decryptedkey2 = engine2.finish(decryptedkey1)
        if decryptedkey2 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        decryptedkey3 = engine1.finish(decryptedkey2)
        if decryptedkey3 == b"":
            raise Exception("Integrity failure: Invalid passphrase or corrupted data")
        else:
            return decryptedkey3
