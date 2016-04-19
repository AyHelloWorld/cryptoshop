#!/usr/bin/env python
# -*-coding:Utf-8 -*

# Cryptoshop Strong file encryption.
# Encrypt and decrypt file in CTR mode with AES, Serpent or Twofish as secure as possible.
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
from modules.appversion import version


def generate_nonce_timestamp():
    """Generate pseudo-random number and seconds since epoch (UTC)."""
    unique_uuid = uuid.uuid4()
    nonce = version + unique_uuid.bytes
    return nonce
