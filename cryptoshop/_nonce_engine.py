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

import uuid
import botan

count = 1


def generate_nonce_timestamp():
    """Generate unique nonce with uuid timestamp (UTC)."""
    global count
    test = "{0:0{1}d}".format(count, 8)
    uniqueuuid = uuid.uuid4().bytes
    rng = botan.rng().get(96)
    tmpnonce = bytes(test.encode('utf-8')) + uniqueuuid + rng
    nonce = tmpnonce[:96]
    count += 1
    return nonce
