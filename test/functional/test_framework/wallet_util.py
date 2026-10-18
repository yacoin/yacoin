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
- To build and sign transactions with explicit keys (token inputs, which
  the wallet can't sign, or invalid amounts), use yac_tx.py.
"""
from decimal import Decimal
import os
import shutil

from test_framework.messages import COIN, MIN_TX_FEE
from test_framework.util import assert_greater_than_or_equal

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
