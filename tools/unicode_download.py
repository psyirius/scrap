#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

if sys.hexversion < 0x3080:
    import platform

    raise RuntimeError('Python 3.8 or higher is needed!\nGot %s instead.' % platform.python_version())

import os
from os import path
from urllib import request


def urljoin(*args) -> str:
    return '/'.join(args)


def mkdirp(_dir) -> None:
    os.makedirs(_dir, exist_ok=True)


unicode_url = 'https://unicode.org'
unicode_public_url = urljoin(unicode_url, 'Public')

version = '14.0.0'

base_url = urljoin(unicode_public_url, version, 'ucd')
print(base_url)

self_dir = path.dirname(__file__)
dest_dir = path.join(self_dir, '..', 'data', 'unicode')

files = (
    'CaseFolding.txt',
    'DerivedNormalizationProps.txt',
    'PropList.txt',
    'SpecialCasing.txt',
    'CompositionExclusions.txt',
    'ScriptExtensions.txt',
    'UnicodeData.txt',
    'DerivedCoreProperties.txt',
    'NormalizationTest.txt',
    'Scripts.txt',
    'PropertyValueAliases.txt',
    ('emoji/emoji-data.txt', 'emoji-data.txt'),
)

# Ensure output directory exists
mkdirp(dest_dir)

for file in files:
    dest_file = file

    if isinstance(file, tuple):
        file, dest_file = file

    url = urljoin(base_url, file)
    dest = path.join(dest_dir, dest_file)

    print(f'Downloading: {url} -> {path.relpath(dest, self_dir)}')

    # Download file
    request.urlretrieve(url, dest)
