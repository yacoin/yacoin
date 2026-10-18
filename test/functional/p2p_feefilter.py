#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the feefilter message a peer sends to the node.

YACoin nodes don't send feefilter themselves; this tests the receiving side.
Fee rates are in base units (10^-6 YAC) per kB.
- With a filter of 100000 (0.1 YAC/kB), a tx paying 0.01 YAC (about 50000)
  is not announced to the peer, a tx paying 1 YAC is; the other node gets
  both. A tx paying exactly the filter rate is announced, one below it isn't.
- feefilter 0 removes the filter; a tx filtered out before isn't announced
  later.
- A feefilter above MAX_MONEY is ignored; MAX_MONEY is accepted.
- Known bug: the log line shows the rate with 8 decimals, so 0.1 YAC/kB reads
  0.00100000 YAC/kB.

The peer is whitelisted, so the node sends it tx invs on every pass of its
send loop instead of on a random timer.
"""
from decimal import Decimal
import re

from test_framework.messages import COIN, MAX_MONEY, MSG_TX, CTransaction, FromHex, msg_feefilter
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, wait_until

FILTER = 100000


class TxInvs(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_invs = []

    def on_inv(self, message):
        self.tx_invs.extend(inv.hash for inv in message.inv if inv.type == MSG_TX)


class FeeFilterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-whitelist=127.0.0.1"], []]

    def run_test(self):
        node = self.nodes[0]
        self.spent = set()
        self.peer = node.add_p2p_connection(TxInvs())
        self.test_filter()
        self.test_boundary()
        self.test_no_filter()
        self.test_range()

    def signed_tx(self, fee):
        """A signed tx from node 0's wallet paying fee (YAC), not sent yet."""
        node = self.nodes[0]
        utxo = next(u for u in node.listunspent() if (u['txid'], u['vout']) not in self.spent)
        self.spent.add((utxo['txid'], utxo['vout']))
        raw = node.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}],
                                        {node.getnewaddress(): Decimal(utxo['amount']) - Decimal(fee)})
        tx = FromHex(CTransaction(), node.signrawtransaction(raw)['hex'])
        tx.rehash()
        return tx

    @staticmethod
    def rate(tx, fee):
        return int(Decimal(fee) * COIN) * 1000 // len(tx.serialize())

    def send(self, tx):
        node = self.nodes[0]
        node.sendrawtransaction(tx.serialize().hex())
        assert_equal(node.getmempoolentry(tx.hash)['size'], len(tx.serialize()))

    def set_filter(self, feerate):
        with self.nodes[0].assert_debug_log(["received: feefilter of"]):
            self.peer.send_and_ping(msg_feefilter(feerate))

    def announced(self, tx):
        with mininode_lock:
            return tx.sha256 in self.peer.tx_invs

    def wait_announced(self, tx):
        wait_until(lambda: tx.sha256 in self.peer.tx_invs, timeout=30, lock=mininode_lock)

    def send_low_high(self):
        """Send a tx below the filter, then one above it; when the second is
        announced, the first was considered in the same or an earlier pass."""
        low, high = self.signed_tx("0.01"), self.signed_tx("1")
        assert self.rate(low, "0.01") < FILTER < self.rate(high, "1")
        self.send(low)
        self.send(high)
        self.wait_announced(high)
        return low, high

    def test_filter(self):
        node, other = self.nodes
        self.log.info("feefilter 100000: a tx paying 0.01 YAC isn't announced, one paying 1 YAC is")
        self.set_filter(FILTER)

        def check():
            with node.assert_debug_log(["received: feefilter of 0.1"]):
                self.peer.send_and_ping(msg_feefilter(FILTER))
        self.known_failure("fee rate log format (t2B49V3R item 3)", check,
                           re.compile(r"received: feefilter of 0\.00100000 YAC/kB"))

        self.low, high = self.send_low_high()
        assert not self.announced(self.low)
        self.log.info("The filter is per peer: the other node gets both")
        wait_until(lambda: {self.low.hash, high.hash} <= set(other.getrawmempool()), timeout=60)

    def test_boundary(self):
        self.log.info("A tx paying exactly the filter rate is announced, one below it isn't")
        tx = self.signed_tx("0.02")
        self.set_filter(self.rate(tx, "0.02"))
        self.send(tx)
        self.wait_announced(tx)
        below = self.signed_tx("0.02")
        self.set_filter(self.rate(below, "0.02") + 1)
        self.send(below)
        high = self.signed_tx("1")
        self.send(high)
        self.wait_announced(high)
        assert not self.announced(below)

    def test_no_filter(self):
        self.log.info("feefilter 0: low-fee txs are announced again, but not the one filtered out before")
        self.set_filter(0)
        low = self.signed_tx("0.01")
        self.send(low)
        self.wait_announced(low)
        assert not self.announced(self.low)

    def test_range(self):
        node = self.nodes[0]
        self.log.info("A feefilter above MAX_MONEY is ignored: the previous filter stays")
        self.set_filter(FILTER)
        with node.assert_debug_log([], unexpected_msgs=["received: feefilter of"]):
            self.peer.send_and_ping(msg_feefilter(MAX_MONEY + 1))
        low, _ = self.send_low_high()
        assert not self.announced(low)
        self.log.info("MAX_MONEY is accepted")
        self.set_filter(MAX_MONEY)


if __name__ == '__main__':
    FeeFilterTest().main()
