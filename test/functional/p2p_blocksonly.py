#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -blocksonly and the relay of transactions from whitelisted peers.

- -blocksonly: localrelay false, the version message asks peers not to relay
  transactions; a tx or tx inv from a peer is ignored ("sent in violation of
  protocol") without a penalty.
- -blocksonly -whitelist: a whitelisted peer's tx is accepted and relayed;
  sent again, a tx that is in the mempool is relayed again ("Force relaying
  tx"); a tx below the minimum relay fee (fee 0) is refused and not
  announced; an invalid tx is not relayed ("Not relaying invalid
  transaction") and the peer stays connected.
- -whitelistrelay=0: a whitelisted peer's tx is ignored again; the node's
  own sendrawtransaction still relays.
"""
from decimal import Decimal

from test_framework.messages import MSG_TX, MY_SUBVERSION, REJECT_INSUFFICIENTFEE, CInv, CTransaction, FromHex, msg_inv, msg_tx
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, peers, wait_until


class TxPeer(P2PInterface):
    """Records tx invs and getdata hashes; never asks for anything."""
    def __init__(self):
        super().__init__()
        self.tx_invs = []
        self.requests = []

    def on_inv(self, message):
        self.tx_invs.extend(inv.hash for inv in message.inv if inv.type == MSG_TX)

    def on_getdata(self, message):
        self.requests.extend(inv.hash for inv in message.inv)


class BlocksOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-blocksonly"], []]

    def run_test(self):
        self.spent = set()
        self.test_blocksonly()
        self.test_whitelisted()
        self.test_whitelistrelay_off()

    def signed_tx(self, fee, extra=Decimal(0)):
        """A signed tx from node 1's wallet spending one unused output; it
        pays fee, or extra more than the output holds."""
        node = self.nodes[1]
        utxo = next(u for u in node.listunspent() if (u['txid'], u['vout']) not in self.spent)
        self.spent.add((utxo['txid'], utxo['vout']))
        amount = Decimal(utxo['amount']) - Decimal(fee) + extra
        raw = node.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], {node.getnewaddress(): amount})
        signed = node.signrawtransaction(raw)
        assert signed['complete']
        tx = FromHex(CTransaction(), signed['hex'])
        tx.rehash()
        return tx

    def mininodes(self, node):
        return [p for p in peers(node) if p['subver'] == MY_SUBVERSION.decode()]

    def restart(self, extra_args):
        self.nodes[0].disconnect_p2ps()
        self.restart_node(0, extra_args)
        # Node 1 connects to node 0, so it is a whitelisted inbound peer there.
        connect_nodes(self.nodes[1], 0)

    def test_blocksonly(self):
        node, other = self.nodes
        self.log.info("-blocksonly: localrelay false, and the version asks the peer not to relay")
        assert_equal((node.getnetworkinfo()['localrelay'], other.getnetworkinfo()['localrelay']), (False, True))
        peer = node.add_p2p_connection(TxPeer())
        with mininode_lock:
            assert_equal(peer.last_message['version'].nRelay, 0)

        self.log.info("A tx from a peer is ignored, without a penalty")
        tx = self.signed_tx("0.01")
        with node.assert_debug_log(["transaction sent in violation of protocol peer="]):
            peer.send_and_ping(msg_tx(tx))
        assert tx.hash not in node.getrawmempool()
        assert peer.is_connected
        assert_equal([p['banscore'] for p in self.mininodes(node)], [0])

        self.log.info("A tx inv from a peer is ignored: no getdata")
        tx2 = self.signed_tx("0.01")
        with node.assert_debug_log(["transaction (%s) inv sent in violation of protocol peer=" % tx2.hash]):
            peer.send_and_ping(msg_inv([CInv(MSG_TX, tx2.sha256)]))
        peer.sync_with_ping()
        with mininode_lock:
            assert_equal(peer.requests, [])

    def test_whitelisted(self):
        node, other = self.nodes
        self.log.info("-blocksonly -whitelist: a whitelisted peer's tx is accepted and relayed")
        self.restart(["-blocksonly", "-whitelist=127.0.0.1"])
        sender = node.add_p2p_connection(TxPeer())
        assert_equal([p['whitelisted'] for p in self.mininodes(node)], [True])
        tx = self.signed_tx("0.01")
        sender.send_and_ping(msg_tx(tx))
        assert tx.hash in node.getrawmempool()
        wait_until(lambda: tx.hash in other.getrawmempool(), timeout=60)

        self.log.info("Sent again, a tx in the mempool is relayed again")
        # Whitelisted peers get tx invs on every pass of the send loop.
        listener = node.add_p2p_connection(TxPeer())
        with node.assert_debug_log(["Force relaying tx %s from whitelisted peer=" % tx.hash]):
            sender.send_and_ping(msg_tx(tx))
        wait_until(lambda: tx.sha256 in listener.tx_invs, timeout=30, lock=mininode_lock)

        self.log.info("A tx below the minimum relay fee (fee 0) is refused and not announced")
        refused = self.signed_tx("0")
        sender.send_message(msg_tx(refused))
        sender.wait_for_reject(message=b"tx", code=REJECT_INSUFFICIENTFEE, reason=b"mempool min fee not met", data=refused.sha256)
        assert refused.hash not in node.getrawmempool()
        accepted = self.signed_tx("0.01")
        sender.send_and_ping(msg_tx(accepted))
        # Only transactions in the mempool are announced; if the refused one
        # is queued at all, it is queued before the accepted one.
        wait_until(lambda: accepted.sha256 in listener.tx_invs, timeout=30, lock=mininode_lock)
        with mininode_lock:
            assert refused.sha256 not in listener.tx_invs

        self.log.info("An invalid tx is not relayed; the whitelisted peer stays connected")
        invalid = self.signed_tx("0.01", extra=Decimal(100))
        with node.assert_debug_log(["Not relaying invalid transaction %s from whitelisted peer=" % invalid.hash,
                                    "bad-txns-in-belowout"]):
            sender.send_and_ping(msg_tx(invalid))
        assert sender.is_connected
        assert invalid.hash not in node.getrawmempool()

    def test_whitelistrelay_off(self):
        node = self.nodes[0]
        self.log.info("-whitelistrelay=0: a whitelisted peer's tx is ignored again")
        self.restart(["-blocksonly", "-whitelist=127.0.0.1", "-whitelistrelay=0"])
        peer = node.add_p2p_connection(TxPeer())
        tx = self.signed_tx("0.01")
        with node.assert_debug_log(["transaction sent in violation of protocol peer="]):
            peer.send_and_ping(msg_tx(tx))
        assert tx.hash not in node.getrawmempool()

        self.log.info("The node's own sendrawtransaction still relays")
        txid = node.sendrawtransaction(tx.serialize().hex())
        wait_until(lambda: txid in self.nodes[1].getrawmempool(), timeout=60)


if __name__ == '__main__':
    BlocksOnlyTest().main()
