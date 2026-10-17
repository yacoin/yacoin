#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Useful util functions for testing the wallet.

Rules for porting Bitcoin Core wallet tests to YACoin:
- sendtoaddress, sendfrom and sendmany take useexpiredtimelockutxo before
  their comment arguments: sendtoaddress(address, amount,
  useexpiredtimelockutxo, comment, comment_to, subtractfeefromamount),
  sendfrom(fromaccount, toaddress, amount, useexpiredtimelockutxo, minconf,
  comment, comment_to), sendmany(fromaccount, amounts,
  useexpiredtimelockutxo, minconf, comment, subtractfeefrom). Use named
  arguments (for sendfrom, named arguments that leave out minconf fail).
- Amounts have at most 6 decimals (COIN = 10^6).
- With the default settings the wallet pays at least 0.01 YAC per
  transaction, not a feerate (see expected_fee).
- Coinbases mature after 6 blocks (COINBASE_MATURITY).
- YACoin has no RBF, segwit, walletconflicts, bip125-replaceable,
  getaddressinfo (use validateaddress), fee estimation, importmulti,
  fundrawtransaction or signrawtransactionwithwallet (use
  signrawtransaction).
- dumpprivkey returns {"address_type", "private_key"[, "redeem_script"]}.
- gettransaction has extra Credit, Debit and token_details fields, and
  returns transactions that aren't in the wallet through the txindex.
- Wallet files live at os.path.join(node.datadir, '<name>').
"""
from collections import namedtuple
from decimal import Decimal
import os
import shutil

from test_framework.address import (
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    script_to_p2sh,
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_2,
    OP_3,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    hash160,
    sha256,
)
from test_framework.messages import COIN, COINBASE_MATURITY, MIN_TX_FEE
from test_framework.util import assert_greater_than_or_equal, hex_str_to_bytes

Key = namedtuple('Key', ['privkey',
                         'pubkey',
                         'p2pkh_script',
                         'p2pkh_addr',
                         'p2wpkh_script',
                         'p2wpkh_addr',
                         'p2sh_p2wpkh_script',
                         'p2sh_p2wpkh_redeem_script',
                         'p2sh_p2wpkh_addr'])

Multisig = namedtuple('Multisig', ['privkeys',
                                   'pubkeys',
                                   'p2sh_script',
                                   'p2sh_addr',
                                   'redeem_script',
                                   'p2wsh_script',
                                   'p2wsh_addr',
                                   'p2sh_p2wsh_script',
                                   'p2sh_p2wsh_addr'])

def get_key(node):
    """Generate a fresh key on node

    Returns a named tuple of privkey, pubkey and all address and scripts."""
    addr = node.getnewaddress()
    pubkey = node.getaddressinfo(addr)['pubkey']
    pkh = hash160(hex_str_to_bytes(pubkey))
    return Key(privkey=node.dumpprivkey(addr),
               pubkey=pubkey,
               p2pkh_script=CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG]).hex(),
               p2pkh_addr=key_to_p2pkh(pubkey),
               p2wpkh_script=CScript([OP_0, pkh]).hex(),
               p2wpkh_addr=key_to_p2wpkh(pubkey),
               p2sh_p2wpkh_script=CScript([OP_HASH160, hash160(CScript([OP_0, pkh])), OP_EQUAL]).hex(),
               p2sh_p2wpkh_redeem_script=CScript([OP_0, pkh]).hex(),
               p2sh_p2wpkh_addr=key_to_p2sh_p2wpkh(pubkey))

def get_multisig(node):
    """Generate a fresh 2-of-3 multisig on node

    Returns a named tuple of privkeys, pubkeys and all address and scripts."""
    addrs = []
    pubkeys = []
    for _ in range(3):
        addr = node.getaddressinfo(node.getnewaddress())
        addrs.append(addr['address'])
        pubkeys.append(addr['pubkey'])
    script_code = CScript([OP_2] + [hex_str_to_bytes(pubkey) for pubkey in pubkeys] + [OP_3, OP_CHECKMULTISIG])
    witness_script = CScript([OP_0, sha256(script_code)])
    return Multisig(privkeys=[node.dumpprivkey(addr) for addr in addrs],
                    pubkeys=pubkeys,
                    p2sh_script=CScript([OP_HASH160, hash160(script_code), OP_EQUAL]).hex(),
                    p2sh_addr=script_to_p2sh(script_code),
                    redeem_script=script_code.hex(),
                    p2wsh_script=witness_script.hex(),
                    p2wsh_addr=script_to_p2wsh(script_code),
                    p2sh_p2wsh_script=CScript([OP_HASH160, witness_script, OP_EQUAL]).hex(),
                    p2sh_p2wsh_addr=script_to_p2sh_p2wsh(script_code))

def test_address(node, address, **kwargs):
    """Get address info for `address` and test whether the returned values are as expected."""
    addr_info = node.getaddressinfo(address)
    for key, value in kwargs.items():
        if value is None:
            if key in addr_info.keys():
                raise AssertionError("key {} unexpectedly returned in getaddressinfo.".format(key))
        elif addr_info[key] != value:
            raise AssertionError("key {} value {} did not match expected value {}".format(key, addr_info[key], value))

DEFAULT_PAYTXFEE = Decimal(MIN_TX_FEE) / COIN  # 0.01 YAC, the wallet's -paytxfee default

def expected_fee(size, paytxfee=DEFAULT_PAYTXFEE):
    """Return the fee in YAC the wallet pays for a transaction of size bytes.

    The wallet starts at paytxfee and raises the fee to the larger of
    size * paytxfee / 1000 and size * MIN_TX_FEE / 1000 (both rounded down to
    whole base units) when that is higher (CWallet::CreateTransactionAll,
    GetMinFee)."""
    pay = int(paytxfee * COIN)
    fee = max(pay, size * pay // 1000, size * MIN_TX_FEE // 1000)
    return Decimal(fee) / COIN

def assert_yac_fee(node, txid, paytxfee=DEFAULT_PAYTXFEE):
    """Check the fee of wallet transaction txid against the wallet's fee rule.

    The fee was computed for the size of an earlier attempt, and signature
    sizes vary by a byte, so allow up to 2 bytes per input above the rule."""
    tx = node.gettransaction(txid)
    fee = -tx['fee']
    assert_greater_than_or_equal(fee, 0)
    raw = node.getrawtransaction(txid, 1)
    size = len(raw['hex']) // 2
    expected = expected_fee(size, paytxfee)
    rate = max(paytxfee, Decimal(MIN_TX_FEE) / COIN)
    tolerance = Decimal(int(2 * len(raw['vin']) * rate * COIN) // 1000) / COIN
    if not expected <= fee <= expected + tolerance:
        raise AssertionError("Fee {} of {} ({} bytes) not in [{}, {}]".format(
            fee, txid, size, expected, expected + tolerance))

def coinbase_value(node, block_hash):
    """Return the total value of the coinbase outputs of a block, in YAC."""
    coinbase = node.getrawtransaction(node.getblock(block_hash)['tx'][0], 1)
    return sum(out['value'] for out in coinbase['vout'])

def mature_coinbase_total(node, address):
    """Return the value of the coinbases in the active chain that pay address
    and are mature (depth >= COINBASE_MATURITY, after the fork), in YAC."""
    tip = node.getblockcount()
    total = Decimal(0)
    for height in range(1, tip - COINBASE_MATURITY + 2):
        block_hash = node.getblockhash(height)
        coinbase = node.getrawtransaction(node.getblock(block_hash)['tx'][0], 1)
        total += sum(out['value'] for out in coinbase['vout']
                     if out['scriptPubKey'].get('addresses') == [address])
    return total

def wipe_chain(node, *, wallet=False):
    """Delete a stopped node's chain data, so it starts like a new node.

    Removes the block files and index, the chainstate, the token database,
    the mempool and peer files; with wallet=True also the wallet and its BDB
    environment. The config file and logs stay."""
    assert not node.running
    names = ['blocks', 'chainstate', 'tokens', 'mempool.dat', 'peers.dat']
    if wallet:
        names += ['wallet.dat', 'database', 'db.log']
    for name in names:
        path = os.path.join(node.datadir, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.remove(path)
