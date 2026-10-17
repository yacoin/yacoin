#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test p2p mempool message (BIP35).

The node never offers NODE_BLOOM, so a peer that isn't whitelisted is
disconnected (not banned) for a mempool message. A whitelisted peer gets an
inv of the whole mempool at the node's next send:
- filtered by the peer's feefilter (a rate equal to the filter passes), but
  not by fRelay=0 in its version message;
- nothing at all when the mempool is empty;
- after the request it may getdata those transactions from the mempool,
  but not transactions that entered the mempool later (the same second is
  fine); before any request it gets notfound.

Node 1 (whitelisted) is not connected to node 0, and its transactions are
made before any peer connects, so none of them is ever announced (which
would let getdata serve them from the relay map instead of the mempool).
"""
from test_framework.messages import (
    COIN,
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    MSG_TX,
    msg_feefilter,
    msg_getdata,
    msg_mempool,
)
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, peers, wait_until
from test_framework.yac_tx import P2SH_TRUE_SCRIPT, P2SH_TRUE_SCRIPT_SIG


class InvPeer(P2PInterface):
    """Records invs (without asking for the transactions), txs and notfounds.
    relay=0 announces fRelay=0 in the version message."""

    def __init__(self, relay=1):
        super().__init__()
        self.relay = relay
        self.invs = []
        self.txs = []
        self.notfound = []

    def peer_connect(self, *args, **kwargs):
        create_conn = super().peer_connect(*args, **kwargs)
        self.on_connection_send_msg.nRelay = self.relay
        return create_conn

    def on_inv(self, message):
        self.invs.append([(i.type, "%064x" % i.hash) for i in message.inv])

    def on_tx(self, message):
        message.tx.rehash()
        self.txs.append(message.tx.hash)

    def on_notfound(self, message):
        self.notfound.append(["%064x" % i.hash for i in message.vec])

    def request(self, txs):
        """getdata txs; return (txids received, notfound txids) after a ping."""
        with mininode_lock:
            n_tx, n_notfound = len(self.txs), len(self.notfound)
        self.send_message(msg_getdata([CInv(MSG_TX, tx.sha256) for tx in txs]))
        self.sync_with_ping()
        with mininode_lock:
            return self.txs[n_tx:], sum(self.notfound[n_notfound:], [])

    def mempool_inv(self, expect_inv=True):
        """Send mempool; return the txids of the invs received until the pong.

        The answer goes out with the node's next send, which is skipped
        while another thread holds cs_main, so the pong can overtake it:
        with expect_inv, wait for the inv first."""
        with mininode_lock:
            n_inv = len(self.invs)
        self.send_message(msg_mempool())
        if expect_inv:
            wait_until(lambda: len(self.invs) > n_inv, timeout=10, lock=mininode_lock)
        self.sync_with_ping()
        with mininode_lock:
            invs = sum(self.invs[n_inv:], [])
        assert all(inv_type == MSG_TX for inv_type, _ in invs)
        return sorted(txid for _, txid in invs)


class P2PMempoolTests(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ["-whitelist=127.0.0.1"]]

    def setup_network(self):
        self.setup_nodes()

    def spend(self, utxo, fee):
        """A 93-byte spend of a P2SH_TRUE output."""
        txid, n, value = utxo
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG)]
        tx.vout = [CTxOut(value - fee, P2SH_TRUE_SCRIPT)]
        tx.rehash()
        assert_equal(len(tx.serialize()), 93)
        assert_equal(self.nodes[1].sendrawtransaction(tx.serialize().hex()), tx.hash)
        return tx

    def run_test(self):
        self.test_not_whitelisted()

        node = self.nodes[1]
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(node, 8, sync=False)
        coin = [u for u in node.listunspent() if u['amount'] > 1][0]
        fund = CTransaction()
        fund.nTime = self.mocktime
        fund.vin = [CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']))]
        value = (int(coin['amount'] * COIN) - COIN // 10) // 6
        fund.vout = [CTxOut(value, P2SH_TRUE_SCRIPT) for _ in range(6)]
        fund = FromHex(CTransaction(), node.signrawtransaction(fund.serialize().hex())['hex'])
        fund.rehash()
        node.sendrawtransaction(fund.serialize().hex())
        self.mine_with_mocktime(node, 1, sync=False)
        self.utxos = [(fund.sha256, i, value) for i in range(6)]

        # 10,000, 30,000 and 100,000 base units per kB
        self.low = self.spend(self.utxos[0], 930)
        self.mid = self.spend(self.utxos[1], 2790)
        self.high = self.spend(self.utxos[2], 9300)

        self.test_whitelisted()
        self.test_no_relay()
        self.test_feefilter()
        self.test_empty_mempool()

    def test_not_whitelisted(self):
        node = self.nodes[0]
        self.log.info("A peer that isn't whitelisted is disconnected for mempool, not banned")
        node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["mempool request with bloom filters disabled, disconnect peer="]):
            node.p2p.send_message(msg_mempool())
            node.p2p.wait_for_disconnect()
        wait_until(lambda: peers(node) == [], timeout=10)
        assert_equal(node.listbanned(), [])
        node.disconnect_p2ps()

    def disconnect_all(self):
        node = self.nodes[1]
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [], timeout=10)

    def test_whitelisted(self):
        node = self.nodes[1]
        low, mid, high = self.low, self.mid, self.high
        self.log.info("A whitelisted peer: notfound before the request, the whole mempool after it")
        peer = node.add_p2p_connection(InvPeer())
        assert_equal([p['whitelisted'] for p in peers(node)], [True])
        assert_equal(peer.request([low]), ([], [low.hash]))
        assert_equal(peer.mempool_inv(), sorted([low.hash, mid.hash, high.hash]))
        assert_equal(peer.request([low, mid]), ([low.hash, mid.hash], []))
        self.disconnect_all()

    def test_no_relay(self):
        node = self.nodes[1]
        self.log.info("A peer with fRelay=0 still gets the mempool inv")
        peer = node.add_p2p_connection(InvPeer(relay=0))
        assert_equal([p['relaytxes'] for p in peers(node)], [False])
        assert_equal(peer.mempool_inv(), sorted([self.low.hash, self.mid.hash, self.high.hash]))

        self.log.info("A transaction newer than the request isn't served; after the next request it is")
        self.set_mocktime(self.mocktime + 1)
        self.newer = self.spend(self.utxos[3], 930)
        assert_equal(peer.request([self.newer]), ([], [self.newer.hash]))
        with mininode_lock:
            assert_equal(sum(peer.invs[1:], []), [])  # fRelay=0: never announced
        assert self.newer.hash in peer.mempool_inv()
        assert_equal(peer.request([self.newer]), ([self.newer.hash], []))

        self.log.info("A transaction from the same second as the request is served")
        self.same_second = self.spend(self.utxos[4], 930)
        assert_equal(peer.request([self.same_second]), ([self.same_second.hash], []))
        self.disconnect_all()

    def test_feefilter(self):
        node = self.nodes[1]
        self.log.info("The mempool inv leaves out transactions below the peer's feefilter")
        peer = node.add_p2p_connection(InvPeer())
        peer.send_message(msg_feefilter(30000))
        # LOW, NEWER and SAME_SECOND pay 10,000 per kB; MID's 30,000 equals the filter.
        assert_equal(peer.mempool_inv(), sorted([self.mid.hash, self.high.hash]))
        self.disconnect_all()

    def test_empty_mempool(self):
        node = self.nodes[1]
        self.log.info("An empty mempool gives no inv at all")
        self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getrawmempool(), [])
        peer = node.add_p2p_connection(InvPeer())
        assert_equal(peer.mempool_inv(expect_inv=False), [])
        with mininode_lock:
            assert_equal(peer.invs, [])


if __name__ == '__main__':
    P2PMempoolTests().main()
