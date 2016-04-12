#!/usr/bin/env python3
# -*-coding:Utf-8 -*

from py_cryptoshop import encryptfile
from py_cryptoshop import decryptfile

result = encryptfile(filename="test", passphrase="mypassword", algo="srp")
print(result["success"])

result2 = decryptfile(filename="test.cryptoshop", passphrase="mypassword")
print(result2["success"])
