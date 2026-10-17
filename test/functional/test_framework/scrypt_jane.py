#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""YACoin's block hash in pure Python (test-only, slow).

The node identifies a block by scrypt-jane over its packed header
(CBlockHeader::CalculateHash, src/primitives/block.h), as built with
-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA (src/Makefile.am):
- password = salt = the header: 84 bytes (64-bit nTime) for version >= 7,
  80 bytes (32-bit nTime) below;
- PBKDF2-HMAC with the original Keccak-512 (padding 0x01, not SHA3-512, so
  hashlib can't be used), one iteration;
- ROMix with the ChaCha20/8 BlockMix, N = 2^(Nfactor + 1), r = p = 1;
- Nfactor = -nFactorAtHardfork (util.NFACTOR_AT_HARDFORK, written into
  every test node's config) from version 7 on; below that it grows with the
  block time (block_nfactor).
The 32-byte result is a little-endian uint256, compared with the target
from nBits. One hash takes about 10 ms, so this is for identifying blocks;
blocktools.solve_block grinds nonces through the node instead.

A test that starts nodes with another -nFactorAtHardfork gets wrong hashes
here (blocktools.solve_block then fails its cross-check).
"""
import struct

from .util import NFACTOR_AT_HARDFORK

# Blocks with a higher Nfactor (pre-fork blocks with times after mid-2013)
# take seconds per hash here; use blocktools.block_hash_rpc for them.
MAX_PYTHON_NFACTOR = 8

_M32 = 0xffffffff
_M64 = (1 << 64) - 1
_KECCAK_RATE = 72  # bytes: (1600 - 2 * 512) / 8
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

def _keccak_f(s):
    """Keccak-f[1600] on a list of 25 lanes, in place (unrolled for speed)."""
    (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = s
    for rc in _KECCAK_RC:
        # theta
        c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
        c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
        c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
        c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
        c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & _M64)
        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & _M64)
        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & _M64)
        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & _M64)
        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & _M64)
        a0, a5, a10, a15, a20 = a0 ^ d0, a5 ^ d0, a10 ^ d0, a15 ^ d0, a20 ^ d0
        a1, a6, a11, a16, a21 = a1 ^ d1, a6 ^ d1, a11 ^ d1, a16 ^ d1, a21 ^ d1
        a2, a7, a12, a17, a22 = a2 ^ d2, a7 ^ d2, a12 ^ d2, a17 ^ d2, a22 ^ d2
        a3, a8, a13, a18, a23 = a3 ^ d3, a8 ^ d3, a13 ^ d3, a18 ^ d3, a23 ^ d3
        a4, a9, a14, a19, a24 = a4 ^ d4, a9 ^ d4, a14 ^ d4, a19 ^ d4, a24 ^ d4
        # rho and pi
        b0 = a0
        b1 = ((a6 << 44) | (a6 >> 20)) & _M64
        b6 = ((a9 << 20) | (a9 >> 44)) & _M64
        b9 = ((a22 << 61) | (a22 >> 3)) & _M64
        b22 = ((a14 << 39) | (a14 >> 25)) & _M64
        b14 = ((a20 << 18) | (a20 >> 46)) & _M64
        b20 = ((a2 << 62) | (a2 >> 2)) & _M64
        b2 = ((a12 << 43) | (a12 >> 21)) & _M64
        b12 = ((a13 << 25) | (a13 >> 39)) & _M64
        b13 = ((a19 << 8) | (a19 >> 56)) & _M64
        b19 = ((a23 << 56) | (a23 >> 8)) & _M64
        b23 = ((a15 << 41) | (a15 >> 23)) & _M64
        b15 = ((a4 << 27) | (a4 >> 37)) & _M64
        b4 = ((a24 << 14) | (a24 >> 50)) & _M64
        b24 = ((a21 << 2) | (a21 >> 62)) & _M64
        b21 = ((a8 << 55) | (a8 >> 9)) & _M64
        b8 = ((a16 << 45) | (a16 >> 19)) & _M64
        b16 = ((a5 << 36) | (a5 >> 28)) & _M64
        b5 = ((a3 << 28) | (a3 >> 36)) & _M64
        b3 = ((a18 << 21) | (a18 >> 43)) & _M64
        b18 = ((a17 << 15) | (a17 >> 49)) & _M64
        b17 = ((a11 << 10) | (a11 >> 54)) & _M64
        b11 = ((a7 << 6) | (a7 >> 58)) & _M64
        b7 = ((a10 << 3) | (a10 >> 61)) & _M64
        b10 = ((a1 << 1) | (a1 >> 63)) & _M64
        # chi and iota
        a0, a1, a2, a3, a4 = (
            b0 ^ (~b1 & b2),
            b1 ^ (~b2 & b3),
            b2 ^ (~b3 & b4),
            b3 ^ (~b4 & b0),
            b4 ^ (~b0 & b1))
        a5, a6, a7, a8, a9 = (
            b5 ^ (~b6 & b7),
            b6 ^ (~b7 & b8),
            b7 ^ (~b8 & b9),
            b8 ^ (~b9 & b5),
            b9 ^ (~b5 & b6))
        a10, a11, a12, a13, a14 = (
            b10 ^ (~b11 & b12),
            b11 ^ (~b12 & b13),
            b12 ^ (~b13 & b14),
            b13 ^ (~b14 & b10),
            b14 ^ (~b10 & b11))
        a15, a16, a17, a18, a19 = (
            b15 ^ (~b16 & b17),
            b16 ^ (~b17 & b18),
            b17 ^ (~b18 & b19),
            b18 ^ (~b19 & b15),
            b19 ^ (~b15 & b16))
        a20, a21, a22, a23, a24 = (
            b20 ^ (~b21 & b22),
            b21 ^ (~b22 & b23),
            b22 ^ (~b23 & b24),
            b23 ^ (~b24 & b20),
            b24 ^ (~b20 & b21))
        a0 ^= rc
    s[:] = [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24]


def _absorb(state, data):
    """Keccak-512 of data with the sponge starting from state (a copy is used)."""
    s = list(state)
    padded = bytearray(data + b"\x01" + b"\x00" * ((-len(data) - 1) % _KECCAK_RATE))
    padded[-1] |= 0x80
    for off in range(0, len(padded), _KECCAK_RATE):
        words = struct.unpack_from("<9Q", padded, off)
        for i in range(9):
            s[i] ^= words[i]
        _keccak_f(s)
    return struct.pack("<8Q", *s[:8])


def _absorb_block(block):
    """Sponge state after absorbing exactly one 72-byte block."""
    s = [0] * 25
    for i, word in enumerate(struct.unpack("<9Q", block)):
        s[i] = word
    _keccak_f(s)
    return s


def keccak512(data):
    """Original Keccak-512 (as scrypt-jane-hash_keccak.h)."""
    return _absorb([0] * 25, data)


def _chacha8(x):
    """ChaCha20/8 core with feed-forward on 16 uint32 words."""
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = x
    for _ in range(4):
        # column round
        x0 = (x0 + x4) & _M32; t = x12 ^ x0; x12 = ((t << 16) | (t >> 16)) & _M32
        x8 = (x8 + x12) & _M32; t = x4 ^ x8; x4 = ((t << 12) | (t >> 20)) & _M32
        x0 = (x0 + x4) & _M32; t = x12 ^ x0; x12 = ((t << 8) | (t >> 24)) & _M32
        x8 = (x8 + x12) & _M32; t = x4 ^ x8; x4 = ((t << 7) | (t >> 25)) & _M32
        x1 = (x1 + x5) & _M32; t = x13 ^ x1; x13 = ((t << 16) | (t >> 16)) & _M32
        x9 = (x9 + x13) & _M32; t = x5 ^ x9; x5 = ((t << 12) | (t >> 20)) & _M32
        x1 = (x1 + x5) & _M32; t = x13 ^ x1; x13 = ((t << 8) | (t >> 24)) & _M32
        x9 = (x9 + x13) & _M32; t = x5 ^ x9; x5 = ((t << 7) | (t >> 25)) & _M32
        x2 = (x2 + x6) & _M32; t = x14 ^ x2; x14 = ((t << 16) | (t >> 16)) & _M32
        x10 = (x10 + x14) & _M32; t = x6 ^ x10; x6 = ((t << 12) | (t >> 20)) & _M32
        x2 = (x2 + x6) & _M32; t = x14 ^ x2; x14 = ((t << 8) | (t >> 24)) & _M32
        x10 = (x10 + x14) & _M32; t = x6 ^ x10; x6 = ((t << 7) | (t >> 25)) & _M32
        x3 = (x3 + x7) & _M32; t = x15 ^ x3; x15 = ((t << 16) | (t >> 16)) & _M32
        x11 = (x11 + x15) & _M32; t = x7 ^ x11; x7 = ((t << 12) | (t >> 20)) & _M32
        x3 = (x3 + x7) & _M32; t = x15 ^ x3; x15 = ((t << 8) | (t >> 24)) & _M32
        x11 = (x11 + x15) & _M32; t = x7 ^ x11; x7 = ((t << 7) | (t >> 25)) & _M32
        # diagonal round
        x0 = (x0 + x5) & _M32; t = x15 ^ x0; x15 = ((t << 16) | (t >> 16)) & _M32
        x10 = (x10 + x15) & _M32; t = x5 ^ x10; x5 = ((t << 12) | (t >> 20)) & _M32
        x0 = (x0 + x5) & _M32; t = x15 ^ x0; x15 = ((t << 8) | (t >> 24)) & _M32
        x10 = (x10 + x15) & _M32; t = x5 ^ x10; x5 = ((t << 7) | (t >> 25)) & _M32
        x1 = (x1 + x6) & _M32; t = x12 ^ x1; x12 = ((t << 16) | (t >> 16)) & _M32
        x11 = (x11 + x12) & _M32; t = x6 ^ x11; x6 = ((t << 12) | (t >> 20)) & _M32
        x1 = (x1 + x6) & _M32; t = x12 ^ x1; x12 = ((t << 8) | (t >> 24)) & _M32
        x11 = (x11 + x12) & _M32; t = x6 ^ x11; x6 = ((t << 7) | (t >> 25)) & _M32
        x2 = (x2 + x7) & _M32; t = x13 ^ x2; x13 = ((t << 16) | (t >> 16)) & _M32
        x8 = (x8 + x13) & _M32; t = x7 ^ x8; x7 = ((t << 12) | (t >> 20)) & _M32
        x2 = (x2 + x7) & _M32; t = x13 ^ x2; x13 = ((t << 8) | (t >> 24)) & _M32
        x8 = (x8 + x13) & _M32; t = x7 ^ x8; x7 = ((t << 7) | (t >> 25)) & _M32
        x3 = (x3 + x4) & _M32; t = x14 ^ x3; x14 = ((t << 16) | (t >> 16)) & _M32
        x9 = (x9 + x14) & _M32; t = x4 ^ x9; x4 = ((t << 12) | (t >> 20)) & _M32
        x3 = (x3 + x4) & _M32; t = x14 ^ x3; x14 = ((t << 8) | (t >> 24)) & _M32
        x9 = (x9 + x14) & _M32; t = x4 ^ x9; x4 = ((t << 7) | (t >> 25)) & _M32
    return [(a + b) & _M32 for a, b in zip(x, (x0, x1, x2, x3, x4, x5, x6, x7,
                                                x8, x9, x10, x11, x12, x13, x14, x15))]


def _blockmix(b):
    """scrypt-jane's ChunkMix for r = 1: b is two 64-byte blocks as 32 words."""
    y0 = _chacha8([p ^ q for p, q in zip(b[16:], b[:16])])
    y1 = _chacha8([p ^ q for p, q in zip(y0, b[16:])])
    return y0 + y1


def scrypt_jane(password, salt, nfactor, dklen=32):
    """scrypt-jane (Keccak-512, ChaCha20/8) with r = p = 1, as YACoin uses it."""
    key = password if len(password) <= _KECCAK_RATE else keccak512(password)
    key = key + b"\x00" * (_KECCAK_RATE - len(key))
    inner = _absorb_block(bytes(k ^ 0x36 for k in key))
    outer = _absorb_block(bytes(k ^ 0x5c for k in key))

    def pbkdf2(msg, nbytes):
        # One iteration: T_i = HMAC(password, msg || be32(i)).
        out = b""
        for i in range(1, (nbytes + 63) // 64 + 1):
            out += _absorb(outer, _absorb(inner, msg + struct.pack(">I", i)))
        return out[:nbytes]

    n = 1 << (nfactor + 1)
    x = list(struct.unpack("<32I", pbkdf2(salt, 128)))
    v = []
    for _ in range(n):
        v.append(x)
        x = _blockmix(x)
    for _ in range(n):
        j = x[16] & (n - 1)
        x = _blockmix([p ^ q for p, q in zip(x, v[j])])
    return pbkdf2(struct.pack("<32I", *x), dklen)


# Pre-fork Nfactor schedule (mainnet, block.h): (first time with the next Nfactor, Nfactor).
_NFACTOR_STEPS = [
    (1368515488, 4), (1368777632, 5), (1369039776, 6), (1369826208, 7),
    (1370088352, 8), (1372185504, 9), (1373234080, 10), (1376379808, 11),
    (1380574112, 12), (1384768416, 13), (1401545632, 14), (1409934240, 15),
    (1435100064, 16), (1468654496, 17), (1502208928, 18), (1602872224, 19),
    (1636426656, 20), (1904862112, 21), (2173297568, 22), (2441733024, 23),
    (3247039392, 24), (3515474848, 25),
]
MAXIMUM_N_FACTOR = 25


def block_nfactor(version, ntime):
    """The Nfactor the node hashes a header with."""
    if version >= 7:
        return NFACTOR_AT_HARDFORK
    for limit, nfactor in _NFACTOR_STEPS:
        if ntime < limit:
            return nfactor
    return MAXIMUM_N_FACTOR


def yac_block_hash(header):
    """The node's block hash (32 bytes, little-endian) of a serialized header.

    header is the 84-byte (version >= 7) or 80-byte (older) serialization;
    version and nTime are read from it."""
    version = struct.unpack_from("<i", header, 0)[0]
    if version >= 7:
        assert len(header) == 84, "a version %d header has 84 bytes, not %d" % (version, len(header))
        ntime = struct.unpack_from("<q", header, 68)[0]
    else:
        assert len(header) == 80, "a version %d header has 80 bytes, not %d" % (version, len(header))
        ntime = struct.unpack_from("<I", header, 68)[0]
    nfactor = block_nfactor(version, ntime)
    if nfactor > MAX_PYTHON_NFACTOR:
        raise NotImplementedError("Nfactor %d is too slow in Python; use blocktools.block_hash_rpc" % nfactor)
    return scrypt_jane(header, header, nfactor)
