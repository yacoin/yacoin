#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build and sign YACoin transactions in Python.

For transactions the wallet won't make: hand-built token scripts, invalid
amounts, CLTV/CSV spends with chosen lock values, version 1 transactions.
(The wallet can't sign token inputs at all: CombineSignatures has no token
case.)

Rules the node checks that these helpers leave to the caller:
- tx.nTime must be at least the nTime of every spent output
  (bad-txns-spent-too-early) and at most the time of the block that
  includes the transaction.
- nVersion and nTime are signed, so set them (to_v1 for a version 1
  transaction) before signing.
- A CLTV spend needs nLockTime >= the script's lock time and an nSequence
  below 0xffffffff; a CSV spend needs nVersion 2 and nSequence = the
  script's value.

Example, spending a P2PKH output of TestNode.PRIV_KEYS[0]:

    key = key_from_wif(TestNode.PRIV_KEYS[0].key)
    tx = CTransaction()
    tx.nTime = self.mocktime
    tx.vin = [CTxIn(COutPoint(int(txid, 16), n))]
    tx.vout = [CTxOut(value - fee, p2pkh_script(key.get_pubkey().get_bytes()))]
    sign_p2pkh_input(tx, 0, key)
    node.sendrawtransaction(tx.serialize().hex())
"""
import struct

from .address import SECRET_KEY_VERSION, base58_to_byte
from .key import ECKey
from .messages import CTransaction, ser_string
from .script import (
    CScript,
    CScriptNum,
    LegacySignatureHash,
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_NOP4,
    OP_TRUE,
    SIGHASH_ALL,
    hash160,
)
from .util import assert_equal

OP_YAC_TOKEN = OP_NOP4  # script/script.h


def key_from_wif(wif):
    """The ECKey of a WIF private key (version byte 205, e.g. TestNode.PRIV_KEYS[i].key
    or dumpprivkey(address)['private_key'])."""
    version, payload = base58_to_byte(wif)
    assert_equal(version, SECRET_KEY_VERSION)
    key = ECKey()
    if len(payload) == 33:
        assert_equal(payload[32], 1)
        key.set(payload[:32], True)
    else:
        assert_equal(len(payload), 32)
        key.set(payload, False)
    return key


def p2pkh_script(pubkey):
    return CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])


def p2sh_script(redeem_script):
    return CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL])


def cltv_p2sh_redeem_script(locktime, pubkey):
    """The wallet's CLTV redeem script (createcltvaddress, GetScriptForCltvP2SH).
    The lock value is pushed as data (CScriptNum), never as OP_N."""
    return CScript([CScriptNum(locktime), OP_CHECKLOCKTIMEVERIFY, OP_DROP, pubkey, OP_CHECKSIG])


def csv_p2sh_redeem_script(sequence, pubkey):
    """The wallet's CSV redeem script (createcsvaddress, GetScriptForCsvP2SH)."""
    return CScript([CScriptNum(sequence), OP_CHECKSEQUENCEVERIFY, OP_DROP, pubkey, OP_CHECKSIG])


# Anyone-can-spend P2SH outputs: spending one needs no signature, so the size
# of a spend is fixed (one P2SH_TRUE input to one P2SH_TRUE output is 93
# bytes). Both sides are standard: P2SH_TRUE_SCRIPT is P2SH, and a redeem
# script that is no template is standard with up to 21 sigops
# (AreInputsStandard).
TRUE_REDEEM_SCRIPT = CScript([OP_TRUE])
P2SH_TRUE_SCRIPT = p2sh_script(TRUE_REDEEM_SCRIPT)
P2SH_TRUE_SCRIPT_SIG = CScript([bytes(TRUE_REDEEM_SCRIPT)])


def sign_input(tx, i, key, script_code, hashtype=SIGHASH_ALL):
    """The signature (DER plus the hashtype byte) of input i over script_code."""
    sighash, err = LegacySignatureHash(CScript(script_code), tx, i, hashtype)
    assert err is None, err
    return key.sign_ecdsa(sighash) + bytes([hashtype])


def sign_p2pkh_input(tx, i, key, script_pubkey=None, hashtype=SIGHASH_ALL):
    """Sign input i, which spends script_pubkey (by default the key's P2PKH
    script; for a token output pass its whole script), with scriptSig
    [sig, pubkey]. Rehashes tx: a version 1 txid covers the scriptSigs."""
    pubkey = key.get_pubkey().get_bytes()
    if script_pubkey is None:
        script_pubkey = p2pkh_script(pubkey)
    tx.vin[i].scriptSig = CScript([sign_input(tx, i, key, script_pubkey, hashtype), pubkey])
    tx.rehash()


def sign_p2sh_input(tx, i, redeem_script, keys, hashtype=SIGHASH_ALL):
    """Sign input i, a P2SH output with this redeem script, with scriptSig
    [sigs..., redeem_script] (OP_0 first for a CHECKMULTISIG script). Rehashes tx."""
    sigs = [sign_input(tx, i, key, redeem_script, hashtype) for key in keys]
    prefix = [OP_0] if CScript(redeem_script)[-1] == OP_CHECKMULTISIG else []
    tx.vin[i].scriptSig = CScript(prefix + sigs + [bytes(redeem_script)])
    tx.rehash()


def to_v1(tx):
    """A version 1 copy of tx (32-bit nTime; the txid covers the scriptSigs).
    Sign after converting."""
    v1 = CTransaction(tx)
    v1.nVersion = 1
    v1.rehash()
    return v1


def _token_script(prefix, payload):
    # prefix is the P2PKH (or other) script the token output pays to. Bytes
    # concatenation: CScript + CScript would push the right side as data.
    return CScript(bytes(prefix) + bytes(CScript([OP_YAC_TOKEN, payload, OP_DROP])))


def _ipfs(ipfs_hash):
    # Only the decoded IPFS hash form: 0x12 0x20 and 32 bytes, written as
    # they are (ReadWriteTokenHash).
    assert len(ipfs_hash) == 34 and ipfs_hash[:2] == b"\x12\x20", "pass a 34-byte decoded IPFS hash"
    return bytes(ipfs_hash)


def token_issue_script(prefix, name, amount, units, reissuable, ipfs_hash=None):
    """Token issue output (CNewToken::ConstructTransaction); amount in base units."""
    payload = b"yacq" + ser_string(name.encode()) + struct.pack("<qbbb", amount, units, int(reissuable), ipfs_hash is not None)
    if ipfs_hash is not None:
        payload += _ipfs(ipfs_hash)
    return _token_script(prefix, payload)


def token_owner_script(prefix, name):
    """Owner token output of an issue (CNewToken::ConstructOwnerTransaction)."""
    return _token_script(prefix, b"yaco" + ser_string((name + "!").encode()))


def token_transfer_script(prefix, name, amount):
    """Token transfer output (CTokenTransfer::ConstructTransaction). amount is
    written as a raw int64, so out-of-range values can be built."""
    return _token_script(prefix, b"yact" + ser_string(name.encode()) + struct.pack("<q", amount))


def token_reissue_script(prefix, name, amount, units=-1, reissuable=True, ipfs_hash=None):
    """Token reissue output (CReissueToken::ConstructTransaction); units -1
    keeps the current units."""
    payload = b"yacr" + ser_string(name.encode()) + struct.pack("<qbb", amount, units, int(reissuable))
    if ipfs_hash is not None:
        payload += _ipfs(ipfs_hash)
    return _token_script(prefix, payload)
