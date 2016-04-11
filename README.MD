py-cryptoshop
===============
***(C)2016 @ CORRAIRE Fabrice***
antidote1911@gmail.com

py_cryptoshop is the crypto module of [Cryptoshop](https://github.com/Antidote1911/Cryptoshop) (a full Qt5 application for use this module
and GnuPG graphically.


General Specifications :
-----------------
py_cryptoshop encrypt files with one of this three algorithms in CTR mode:
- AES-256
- Serpent-256
- Twofish-256

It use Botan. Crypto and TLS library for C++11.
For more information's on Botan, go here:
- http://botan.randombit.net
- https://github.com/randombit/botan
- https://en.wikipedia.org/wiki/Botan_(programming_library)

It use Argon2 for key derivation/stretching and HMAC-Keccak-1600 for message authentication.
For more information's on Argon2:
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
<b>Key derivation/stretching</b>

The user passphrase derivation is performed with the winner of the Password Hashing
competition, Argon2.

Argon2 use a fixed timing calculation and not iterations, to prevent Timing attack.
It generate a 64 bits key with the user passphrase and a random 256 bits salt. This key is
split in two 32 bits keys. One for encryption and one for authentication.

<b>Encryption</b>

You can encrypt with AES-256, Serpent-256, or Twofish-256. If no algorithm is specified,
py_cryptoshop use Serpent-256.

Encryption is optimized for larges files. The file is encrypted chunk by chunk. All encrypted
chunks use a different random 16 bits nonce (or initialization vector if you want...). It is ABSOLUTELY necessary
for CTR mode... NEVER USE THE SAME KEY WITH THE SAME NONCE.

The final cryptoshop format is:

[ header, HMAC, Salt, (nonce1||chunck1), (nonce2||chunck2), (nonce3||chunck3),........ ]

<b>Decryption</b>

The decryption routine check the header before all other operations to check version. She decrypt the file
chunk by chunk with etch corresponding nonce. The authentication is updated with all encrypted chunks.

<b>3- Authentication</b>

Authentication is performed by HMAC(Keccak-1600). Keccak-1600 is the Winner Of SHA-3 Competition.

More information's here:
- https://en.wikipedia.org/wiki/SHA-3
- http://keccak.noekeon.org/

The authentication code is calculated with header, salt and etch nonce/encrypted chunk.
It is applied on all encrypted chunk and NOT ON CLEAR CHUNK to prevent padding-oracle attacks vulnerability
when it is applied on the plaintext.
The decryption routine read the hmac code in the encrypted file, and compare it with the calculated.
py_cryptoshop use a constant timing algorithm verification to prevent Timing Attack. Not a trivial
<i>if hamac1 == hmac2</i>

###Requirement
- Python >= 3
- Botan library >= 1.29 <---  py_cryptoshop don't work with old branch of Botan (1.10)

Python modules:
- tqdm  <--- console progress-bar
- argon2_cffi <--- Python module/wrapper for Argon2
- botan <--- Botan Python module/wrapper is installed with the Botan library 1.29

###License

- py_cryptoshop is released under [GPL](https://github.com/Antidote1911/py_cryptoshop/blob/master/py_cryptoshop_license) License.
- Botan is released under the permissive [Simplified BSD](http://botan.randombit.net/license.txt) license.
- argon2_cffi and tqdm are released under The [MIT](https://github.com/hynek/argon2_cffi/blob/master/LICENSE) License

###Why py_cryptoshop ?

<i>It's easy to make a bad crypto but is hard to get right...</i>

There is a lot of bad (really really bad...) encryption modules for python.
- no authentication.
- else, authentication routine use naive comparison like <i>if m1==m2 mac is good</i>. This approach permit Timing Attack.
- use unsecured algorithm like ECB mode, MD5 or SHA-1 etc...
- bad use of the encryption mode. Reuse nonce for same key in CTR, fixed initialization vector when it must be random etc...
- Passphrase derivation/stretching with iterative hash function. Good for brute-force ! Hash are NOT make for this usage. Use strong Key Derivation Functions (KDF) algo like Argon2 or PBKDF2.
- Systematically use PyCrypto. This is a good module, but there is no Serpent algo, and some functions like PBKDF2 are very slow because it's a pure Python implementation.
- No optimization for big files.
etc ...

A very good encryption module is [simple-crypt](https://github.com/andrewcooke/simple-crypt) but the usage of PyCrypto eliminate the usage of Serpent, and make PBKDF2 very slow. Finally, it was't designed for encrypt big files.

###Other resources
Same recommendations of the [Botan author](http://botan.randombit.net/):

<i>"You should have some knowledge of cryptography *before* trying to use
or modify this module. This is an area where it is very easy to make mistakes,
and where things are often subtle and/or counterintuitive.

The module tries to provide things at a high level precisely to
minimize the number of ways things can go wrong, but naive modifications will
almost certainly not result in a secure system.

Especially recommended are:

- *Cryptography Engineering*
  by Niels Ferguson, [Bruce Schneier](https://www.schneier.com/), and Tadayoshi Kohno

- *Security Engineering -- A Guide to Building Dependable Distributed Systems*
  by Ross Anderson
  [available online](https://www.cl.cam.ac.uk/~rja14/book.html)

- *Handbook of Applied Cryptography*
by Alfred J. Menezes, Paul C. Van Oorschot, and Scott A. Vanstone
[available online](http://www.cacr.math.uwaterloo.ca/hac/)

If you're doing something non-trivial or unique, you might want to at
the very least ask for review/input on a mailing list such as the
[metzdowd](http://www.metzdowd.com/mailman/listinfo/cryptography) or
[randombit](http://lists.randombit.net/mailman/listinfo/cryptography)
crypto lists. And (if possible) pay a professional cryptographer or
security company to review your design and code."</i>


http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html

https://en.wikipedia.org/wiki/Timing_attack
