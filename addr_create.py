#!/usr/bin/env python
# encoding: utf-8

from ecdsa import SigningKey, SECP256k1
import binascii
import hashlib
import base58
from blake256 import *


# PmQdpJUzswavmn8Li2VWL5uJMTGNX5CHjBNocLQZSP9Cge5x3XAJf
# DsXe9oQMPY3sQ5A3RyqHHeVMDka9uUy5WbY


addr_prefix = b'\x07\x3f'
key_prefix = b'\x22\xde'


def create_priv_pub_key():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string(), vk.to_string()


def get_compressed_wif_key(privkey_bytes):
    assert(type(privkey_bytes) == bytes)
    assert(len(privkey_bytes) == 32)
    b32 = blake_hash(key_prefix + b'\x00' + privkey_bytes)
    key_bytes = key_prefix + b'\x00' + privkey_bytes + b32[0:4]
    return base58.b58encode(key_bytes)


def get_compressed_pubkey(pubkey_uncompressed):
    assert(type(pubkey_uncompressed) == bytes)
    assert(len(pubkey_uncompressed) == 64)

    if pubkey_uncompressed[63] % 2 == 0:
        pubkey_compressed = b'\x02'
    else:
        pubkey_compressed = b'\x03'

    pubkey_compressed = pubkey_compressed + pubkey_uncompressed[0:32]
    return pubkey_compressed


def get_compressed_address(pubkey_compressed):
    assert (type(pubkey_compressed) == bytes)
    assert (len(pubkey_compressed) == 33)

    h = hashlib.new('ripemd160')
    h.update(blake_hash(pubkey_compressed))
    b20 = h.digest()
    b32 = blake_hash(blake_hash(addr_prefix + b20))
    addr_bytes = addr_prefix + b20 + b32[0:4]
    return base58.b58encode(addr_bytes)


def get_p2pkh_script_pubkey(addr_b58_str):
    addr_b58_bytes = base58.b58decode(addr_b58_str)
    assert(addr_b58_bytes[0:2] == addr_prefix)
    assert(len(addr_b58_bytes) == 26)
    return '76a914' + addr_b58_bytes[2:-4].hex() + '88ac'


if __name__ == "__main__":
    privkey_bytes = base58.b58decode("PmQdpJUzswavmn8Li2VWL5uJMTGNX5CHjBNocLQZSP9Cge5x3XAJf")[3:-4]
    wifkey = get_compressed_wif_key(privkey_bytes)
    print(wifkey)
    privkey = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    pubkey = privkey.get_verifying_key()
    pubkey_bytes = pubkey.to_string()
    pubkey_compress_bytes = get_compressed_pubkey(pubkey_bytes)
    print(get_compressed_address(pubkey_compress_bytes))

