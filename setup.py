#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name='Cryptoshop',
    version='1.0',
    packages=find_packages(),
    author="Fabrice Corraire",
    author_email="antidote1911@gmail.com",
    description="Encrypt and decrypt file in CTR mode with AES, Serpent or Twofish as secure as possible.",
    long_description=open('README.md').read(),
    install_requires= ['tqdm','argon2_cffi'],
    include_package_data=True,
    url='https://github.com/Antidote1911/cryptoshop',
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "License :: GPL",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development'
    ],

    license="GPL",
)
