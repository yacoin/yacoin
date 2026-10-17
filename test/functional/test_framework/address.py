#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encode and decode YACoin base58 addresses and keys.

The suite runs on mainnet parameters, so these use mainnet's version bytes
(chainparams.cpp base58Prefixes).
"""

from .script import CScript, hash160, hash256
from .util import hex_str_to_bytes

PUBKEY_ADDRESS_VERSION = 77  # P2PKH addresses start with Y
SCRIPT_ADDRESS_VERSION = 139  # P2SH addresses start with x or y
SECRET_KEY_VERSION = 205  # WIF private keys

chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def byte_to_base58(b, version):
    result = ''
    str = b.hex()
    str = chr(version).encode('latin-1').hex() + str
    checksum = hash256(hex_str_to_bytes(str)).hex()
    str += checksum[:8]
    value = int('0x'+str,0)
    while value > 0:
        result = chars[value % 58] + result
        value //= 58
    while (str[:2] == '00'):
        result = chars[0] + result
        str = str[2:]
    return result


def base58_to_byte(s):
    """Decode a base58check string to (version, payload), checking the checksum."""
    value = 0
    for c in s:
        value = value * 58 + chars.index(c)
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    raw = b'\x00' * (len(s) - len(s.lstrip(chars[0]))) + raw
    assert len(raw) > 4, "base58 string too short"
    data, checksum = raw[:-4], raw[-4:]
    assert hash256(data)[:4] == checksum, "base58 checksum mismatch"
    return data[0], data[1:]


def keyhash_to_p2pkh(hash):
    assert len(hash) == 20
    return byte_to_base58(hash, PUBKEY_ADDRESS_VERSION)


def scripthash_to_p2sh(hash):
    assert len(hash) == 20
    return byte_to_base58(hash, SCRIPT_ADDRESS_VERSION)


def key_to_p2pkh(key):
    key = check_key(key)
    return keyhash_to_p2pkh(hash160(key))


def script_to_p2sh(script):
    script = check_script(script)
    return scripthash_to_p2sh(hash160(script))


def check_key(key):
    if (type(key) is str):
        key = hex_str_to_bytes(key) # Assuming this is hex string
    if (type(key) is bytes and (len(key) == 33 or len(key) == 65)):
        return key
    assert False


def check_script(script):
    if (type(script) is str):
        script = hex_str_to_bytes(script) # Assuming this is hex string
    if (type(script) is bytes or type(script) is CScript):
        return script
    assert False

