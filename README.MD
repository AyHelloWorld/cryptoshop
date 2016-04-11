py-cryptoshop
===============
***(C)2016 @ CORRAIRE Fabrice***
antidote1911@gmail.com

Description :
-----------------
py_cryptoshop is the crypto module of Cryptoshop (a full Qt5 application for use this module
and GnuPG graphically.

Generals Specifications :
-----------------
py_cryptoshop encrypt files with one of this three algorithms in CTR mode:
- AES-256
- Serpent-256
- Twofish-256

It use Botan. Crypto and TLS library for C++11.
For more information on Botan, go here:
- http://botan.randombit.net
- https://github.com/randombit/botan
- https://en.wikipedia.org/wiki/Botan_(programming_library)

It use Argon2 for key derivation/stetching and HMAC-Keccak-1600 for message authentication.
For more information on Argon2:
- https://en.wikipedia.org/wiki/Argon2
- https://www.cryptolux.org/index.php/Argon2
- https://github.com/P-H-C/phc-winner-argon2

py_cryptoshop is optimized for large files.

<b>You can use it like console application:</b>

    # encrypt the file test with AES-256.
    # If no algo is specified, Serpent-256 (-a srp) is default.
    # Encrypted file test.cryptoshop is writed in same folder:
    ./py_cryptoshop -e test -a aes


    # decrypt the file test.cryptoshop.
    # No need to specify algo. It is automatically detected by decryption routine.
    ./py_cryptoshop -d test.cryptoshop


<b>You can use it like module for your python application:</b>

    from py_cryptoshop import encryptfile
    from py_cryptoshop import decryptfile

    result = encryptfile(filename="test", passphrase="mypassphrase", algo="srp")
    print(result["success"])

    result = decryptfile(filename="test.cryptoshop", passphrase="mypassphrase")
    print(result["success"])

Advanced Specifications :
-----------------
<b>1- Key derivation/stretching</b>

The user passphrase derivation is performed with the winner of the Password Hashing
competition, Argon2.

Argon2 use a fixed timing calculation and not iterations, to prevent Timing attack.
It generate a 64 bits key with the user passphrase and a random 256 bits salt. This key is
split in two 32 bits keys. One for encryption and one for authentication.

<b>2- Encryption</b>

You can encrypt with AES-256, Serpent-256, or Twofish-256. If no algorithm is specified,
py_cryptoshop use Serpent-256.

Encryption is optimized for larges files. The file is encrypted chunk by chunk. All encrypted
chunks use a different random 16 bits nonce (or initialization vector if you want...). It is ABSOLUTELY necessary
for CTR mode... NEVER USE THE SAME KEY WITH THE SAME NONCE.
The contenair result is [header, HMAC, Salt, (nonce1||chunck1), (nonce2||chunck2), (nonce3||chunck3),........]

<b>1- Decryption</b>

The decryption routine check the header before all other operations to check version. She decrypt the file
chunk by chunk with etch corresponding nonce. The authentication is updated with all encrypted chunks.

<b>3- Authentication</b>

Authentication is performed by HMAC(Keccak-1600). Keccak-1600 is the Winner Of SHA-3 Competition.
The authentication code is calculated with header, salt and etch nonce/encryped chunk.
It is applied on all encryped chunk and NOT ON CLEAR CHUNK to prevent padding-oracle attacks vulnerability
when it is applied on the plaintext.
The decryption routine read the hmac code in the encrypted file, and compare it with the calculated.
py_cryptoshop use a constant timing algorithm verification to prevent Timing Attack. Not a trivial
if hamac1 == hmac2

<b>4- License</b>
Cryptoshop is under GPL License. See LICENSE text file ( license.gpl ) for more information's.

<b>5- Requirement</b>
Python 3.5
Botan library

Python modules
tqdm  <--- console progress-bar
botan <--- Python module is installed with the library