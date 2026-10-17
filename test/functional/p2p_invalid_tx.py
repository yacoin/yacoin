#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Invalid transactions and orphans received over P2P.

- Orphans: stored, their parent fetched with getdata, accepted (with a
  grandchild) once the parent arrives; an orphan that turns out invalid
  punishes the peer that sent it, not the one that sent the parent; one that
  fails only on policy is dropped without punishment; orphans of a rejected
  parent aren't kept; the orphan pool limit (-maxorphantx), removal when the
  sending peer disconnects, the 20-minute orphan expiry, removal when a block
  spends an orphan's input, getdata for several missing parents, a second
  copy, and orphans too large to keep.
- A policy reject keeps the peer and isn't repeated for a resent tx until
  the tip changes (recentRejects).
- The ban score (0, 10 or 100) and disconnect for each kind of invalid tx.
  The reject codes and reasons of most of these are mempool_accept.py's
  subject; this test is about the scores. Loopback peers are disconnected,
  never banned (p2p_misbehavior_ban.py covers bans).

Every transaction is built in Python from outputs of a key no wallet
holds, and each invalid one spends an output that nothing else spends.
"""
import os
import random
import time

from test_framework.key import ECKey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    MSG_TX,
    REJECT_DUPLICATE,
    REJECT_INSUFFICIENTFEE,
    REJECT_INVALID,
    REJECT_NONSTANDARD,
    msg_tx,
)
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, peers, wait_until
from test_framework.yac_tx import (
    cltv_p2sh_redeem_script,
    key_from_wif,
    p2pkh_script,
    p2sh_script,
    sign_input,
    sign_p2pkh_input,
)

FEE = COIN // 100  # 0.01 YAC, the minimum for a small tx
EACH = COIN // 20  # value of each funding output
N_FUNDING = 40
CLTV_HEIGHT = 1000
# MAX_REJECT_MESSAGE_LENGTH (111) cuts the script error in the reject.
BAD_SIG_REASON = b"mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack e"


class TxPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.getdata_requests = []

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_requests.append((inv.type, inv.hash))


class InvalidTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-maxorphantx=5"]]

    # Helpers

    def connect(self):
        """A new TxPeer, with the node's id for it in peer_id."""
        node = self.nodes[0]
        before = {p['id'] for p in peers(node)}
        conn = node.add_p2p_connection(TxPeer())
        new = [p['id'] for p in peers(node) if p['id'] not in before]
        assert_equal(len(new), 1)
        conn.peer_id = new[0]
        return conn

    def banscore(self, conn):
        for p in peers(self.nodes[0]):
            if p['id'] == conn.peer_id:
                return p['banscore']
        raise AssertionError("peer=%d is not connected" % conn.peer_id)

    def close(self, conn):
        conn.peer_disconnect()
        conn.wait_for_disconnect()

    def rejects(self, conn):
        with mininode_lock:
            return [(r.message, r.code, r.reason, r.data) for r in conn.rejects]

    def next_utxo(self):
        """A funding output nothing has spent yet: (txid int, n, value)."""
        return self.utxos.pop(0)

    def spend(self, utxo, outputs=None, *, sign=True):
        """A tx spending utxo (a K output) to K, minus FEE, signed with K."""
        txid, n, value = utxo
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, n))]
        tx.vout = outputs if outputs is not None else [CTxOut(value - FEE, self.k_script)]
        if sign:
            sign_p2pkh_input(tx, 0, self.key)
        else:
            tx.rehash()
        return tx

    def child(self, parent, *, fee=FEE):
        return self.spend((parent.sha256, 0, parent.vout[0].nValue), [CTxOut(parent.vout[0].nValue - fee, self.k_script)])

    def orphan(self, n_parents=1, n_outputs=1):
        """An orphan whose parents are random txids (no signature needed:
        the node can't check it without the parents)."""
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(random.getrandbits(256), 0)) for _ in range(n_parents)]
        tx.vout = [CTxOut(EACH, self.k_script) for _ in range(n_outputs)]
        tx.rehash()
        return tx

    def debug_log_size(self):
        return os.path.getsize(os.path.join(self.nodes[0].datadir, 'debug.log'))

    def debug_log_since(self, offset):
        with open(os.path.join(self.nodes[0].datadir, 'debug.log'), encoding='utf-8') as f:
            f.seek(offset)
            return f.read()

    def assert_score(self, tx, code, reason, score):
        """Send tx from a new peer: it gets this reject and ban score."""
        node = self.nodes[0]
        conn = self.connect()
        if score < 100:
            conn.send_and_ping(msg_tx(tx))
            assert_equal(self.rejects(conn), [(b"tx", code, reason, tx.sha256)])
            assert_equal(self.banscore(conn), score)
            self.close(conn)
        else:
            with node.assert_debug_log(["peer=%d (0 -> 100) BAN THRESHOLD EXCEEDED" % conn.peer_id,
                                        "Warning: not banning local peer 127.0.0.1:"], timeout=10):
                conn.send_message(msg_tx(tx))
                conn.wait_for_reject(message=b"tx", code=code, reason=reason, data=tx.sha256)
                conn.wait_for_disconnect(timeout=10)
        return reason

    # The test

    def run_test(self):
        self.fund()
        self.test_orphan_then_parent()
        self.test_mempool_duplicates()
        self.test_invalid_orphan()
        self.test_rejected_parent()
        self.test_policy_reject_kept()
        self.test_scores()
        self.test_orphan_limit()
        self.test_orphan_expiry()
        self.test_orphan_conflicted_by_block()
        self.test_orphan_edge_cases()

    def fund(self):
        node = self.nodes[0]
        self.set_mocktime(int(time.time()))
        # Coinbases to PRIV_KEYS[1], which node 0's wallet doesn't hold.
        self.cb_key = key_from_wif(TestNode.PRIV_KEYS[1].key)
        cb_address = TestNode.PRIV_KEYS[1].address
        for _ in range(8):
            self.set_mocktime(self.mocktime + 60)
            node.generatetoaddress(1, cb_address)
        self.key = ECKey()
        self.key.generate()
        pubkey = self.key.get_pubkey().get_bytes()
        self.k_script = p2pkh_script(pubkey)
        self.cltv_redeem = cltv_p2sh_redeem_script(CLTV_HEIGHT, pubkey)

        coinbase = node.getblock(node.getblockhash(1))['tx'][0]
        cb_value = int(round(node.gettxout(coinbase, 0)['value'] * COIN))
        fan = CTransaction()
        fan.nTime = self.mocktime
        fan.vin = [CTxIn(COutPoint(int(coinbase, 16), 0))]
        fan.vout = [CTxOut(EACH, self.k_script) for _ in range(N_FUNDING)]
        fan.vout.append(CTxOut(EACH, p2sh_script(self.cltv_redeem)))
        fan.vout.append(CTxOut(cb_value - (N_FUNDING + 1) * EACH - 5 * FEE, p2pkh_script(self.cb_key.get_pubkey().get_bytes())))
        sign_p2pkh_input(fan, 0, self.cb_key)
        node.sendrawtransaction(fan.serialize().hex())
        node.generatetoaddress(1, cb_address)
        assert_equal(node.getrawmempool(), [])
        self.utxos = [(fan.sha256, i, EACH) for i in range(N_FUNDING)]
        self.cltv_utxo = (fan.sha256, N_FUNDING, EACH)

    def test_orphan_then_parent(self):
        node = self.nodes[0]
        self.log.info("An orphan and its child wait for the parent, which is fetched with getdata")
        self.m1 = self.connect()
        self.p1 = self.spend(self.next_utxo())
        c1 = self.child(self.p1)
        g1 = self.child(c1)
        with node.assert_debug_log(["stored orphan tx %s" % c1.hash, "stored orphan tx %s" % g1.hash]):
            self.m1.send_message(msg_tx(c1))
            self.m1.send_and_ping(msg_tx(g1))
        assert_equal(node.getrawmempool(), [])
        wait_until(lambda: (MSG_TX, self.p1.sha256) in self.m1.getdata_requests, timeout=10, lock=mininode_lock)
        with mininode_lock:
            # g1's parent c1 is a known orphan, so only p1 is requested.
            assert_equal(self.m1.getdata_requests, [(MSG_TX, self.p1.sha256)])
        with node.assert_debug_log(["   accepted orphan tx %s" % c1.hash, "   accepted orphan tx %s" % g1.hash]):
            self.m1.send_and_ping(msg_tx(self.p1))
        assert_equal(sorted(node.getrawmempool()), sorted([self.p1.hash, c1.hash, g1.hash]))
        assert_equal(self.banscore(self.m1), 0)
        assert_equal(self.rejects(self.m1), [])

    def test_mempool_duplicates(self):
        self.log.info("A tx already in the mempool is ignored; a conflicting one gets a reject, no score")
        self.m1.send_and_ping(msg_tx(self.p1))
        assert_equal(self.rejects(self.m1), [])
        assert_equal(self.banscore(self.m1), 0)
        utxo = (self.p1.vin[0].prevout.hash, self.p1.vin[0].prevout.n, EACH)
        conflict = self.spend(utxo, [CTxOut(EACH - 2 * FEE, self.k_script)])
        self.assert_score(conflict, REJECT_DUPLICATE, b"txn-mempool-conflict", 0)

    def test_invalid_orphan(self):
        node = self.nodes[0]
        self.log.info("An orphan with a bad signature punishes its sender, not the parent's sender")
        m2 = self.connect()
        m3 = self.connect()
        p2 = self.spend(self.next_utxo())
        c2 = self.child(p2)
        c2.vout[0].nValue -= 1  # after signing: the signature no longer matches
        c2.rehash()
        with node.assert_debug_log(["stored orphan tx %s" % c2.hash]):
            m2.send_and_ping(msg_tx(c2))
        with node.assert_debug_log(["   invalid orphan tx %s" % c2.hash, "   removed orphan tx %s" % c2.hash,
                                    "peer=%d (0 -> 100) BAN THRESHOLD EXCEEDED" % m2.peer_id], timeout=10):
            m3.send_and_ping(msg_tx(p2))
            m2.wait_for_disconnect(timeout=10)
        assert p2.hash in node.getrawmempool()
        # Orphans are re-checked with a dummy state: no reject for anyone.
        assert_equal(self.rejects(m2), [])
        assert_equal(self.rejects(m3), [])
        assert_equal(self.banscore(m3), 0)

        self.log.info("An orphan that fails only on policy is dropped without punishing its sender")
        m4 = self.connect()
        p2b = self.spend(self.next_utxo())
        c2b = self.child(p2b, fee=1)
        with node.assert_debug_log(["stored orphan tx %s" % c2b.hash]):
            m4.send_and_ping(msg_tx(c2b))
        with node.assert_debug_log(["   removed orphan tx %s" % c2b.hash], ["   invalid orphan tx"]):
            m3.send_and_ping(msg_tx(p2b))
        m4.sync_with_ping()
        assert_equal(self.banscore(m4), 0)
        assert_equal(self.rejects(m4), [])
        assert p2b.hash in node.getrawmempool()
        assert c2b.hash not in node.getrawmempool()
        self.close(m4)
        self.m3 = m3

    def test_rejected_parent(self):
        node = self.nodes[0]
        self.log.info("Orphans of a rejected parent aren't kept")
        utxo = self.next_utxo()
        p3 = self.spend(utxo, [CTxOut(utxo[2] + 1, self.k_script)])
        self.assert_score(p3, REJECT_INVALID, b"bad-txns-in-belowout", 100)
        conn = self.connect()
        c3 = self.child(p3)
        with node.assert_debug_log(["not keeping orphan with rejected parents %s" % c3.hash]):
            conn.send_and_ping(msg_tx(c3))
        # A second copy is filtered out before anything else (recentRejects).
        with node.assert_debug_log([], ["stored orphan", "not keeping orphan"]):
            conn.send_and_ping(msg_tx(c3))
        assert_equal(self.rejects(conn), [])
        assert_equal(self.banscore(conn), 0)
        self.close(conn)

    def test_policy_reject_kept(self):
        node = self.nodes[0]
        self.log.info("A policy reject keeps the peer and isn't repeated until the tip changes")
        tx = self.spend(self.next_utxo(), [CTxOut(EACH - FEE, CScript([OP_TRUE]))])
        conn = self.m1
        conn.send_and_ping(msg_tx(tx))
        expected = (b"tx", REJECT_NONSTANDARD, b"scriptpubkey", tx.sha256)
        assert_equal(self.rejects(conn), [expected])
        assert_equal(self.banscore(conn), 0)
        conn.send_and_ping(msg_tx(tx))
        assert_equal(self.rejects(conn), [expected])
        node.generatetoaddress(1, TestNode.PRIV_KEYS[1].address)
        conn.send_and_ping(msg_tx(tx))
        assert_equal(self.rejects(conn), [expected, expected])
        assert_equal(self.banscore(conn), 0)

    def test_scores(self):
        node = self.nodes[0]
        self.log.info("Ban score 0: policy, fee, immature coinbase, unsatisfied CLTV")
        utxo = self.next_utxo()
        self.assert_score(self.spend(utxo, [CTxOut(utxo[2] - 1, self.k_script)]),
                          REJECT_INSUFFICIENTFEE, b"mempool min fee not met", 0)

        immature = node.getblock(node.getblockhash(node.getblockcount() - 1))['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(immature, 16), 0))]
        tx.vout = [CTxOut(EACH, self.k_script)]
        sign_p2pkh_input(tx, 0, self.cb_key)
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-premature-spend-of-coinbase/coinstake", 0)

        # The mempool checks CLTV (a policy flag here); a failure is a
        # non-mandatory policy reject.
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(self.cltv_utxo[0], self.cltv_utxo[1]), b"", 0xfffffffe)]
        tx.vout = [CTxOut(EACH - FEE, self.k_script)]
        tx.vin[0].scriptSig = CScript([sign_input(tx, 0, self.key, self.cltv_redeem), bytes(self.cltv_redeem)])
        tx.rehash()
        self.assert_score(tx, REJECT_NONSTANDARD, b"non-mandatory-script-verify-flag (Locktime requirement not satisfied)", 0)

        self.log.info("Ban score 10: no inputs, no outputs, a null prevout")
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vout = [CTxOut(EACH, self.k_script)]
        tx.rehash()
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-vin-empty", 10)
        no_outputs = self.assert_score(self.spend(self.next_utxo(), []), REJECT_INVALID, b"bad-txns-vout-empty", 10)
        tx = self.spend(self.next_utxo(), sign=False)
        tx.vin.append(CTxIn(COutPoint(0, 0xffffffff)))  # two inputs: not a coinbase
        tx.rehash()
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-prevout-null", 10)

        self.log.info("Ban score 100, then disconnect")
        empty_txout = self.assert_score(self.spend(self.next_utxo(), [CTxOut(0, CScript())]),
                                        REJECT_INVALID, b"bad-txns-vout-empty", 100)

        def distinct_reasons():
            assert empty_txout != no_outputs, "reason %r used for both" % empty_txout
        self.known_failure("bad-txns-vout-empty reused (LfLSjWq5 item 1)", distinct_reasons,
                           expected="reason b'bad-txns-vout-empty' used for both")

        self.assert_score(self.spend(self.next_utxo(), [CTxOut(-1, self.k_script)]), REJECT_INVALID, b"bad-txns-vout-negative", 100)
        tx = self.spend(self.next_utxo(), sign=False)
        tx.vin.append(tx.vin[0])
        tx.rehash()
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-inputs-duplicate", 100)
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(0, 0xffffffff), b"\x01\x02")]
        tx.vout = [CTxOut(EACH, self.k_script)]
        tx.rehash()
        self.assert_score(tx, REJECT_INVALID, b"coinbase", 100)
        tx = self.spend(self.next_utxo(), sign=False)
        tx.nTime = self.mocktime - 100000  # older than the output it spends
        sign_p2pkh_input(tx, 0, self.key)
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-spent-too-early", 100)
        # Larger than the block size limit (about 380 kB on the test chain).
        tx = self.spend(self.next_utxo(), [CTxOut(EACH - FEE, CScript([b"\x00" * 400000]))])
        self.assert_score(tx, REJECT_INVALID, b"bad-txns-oversize", 100)

        tx = self.spend(self.next_utxo())
        tx.vout[0].nValue -= 1  # after signing
        tx.rehash()
        assert_equal(len(BAD_SIG_REASON), 111)
        self.assert_score(tx, REJECT_INVALID, BAD_SIG_REASON, 100)
        assert_equal(node.listbanned(), [])

    def test_orphan_limit(self):
        node = self.nodes[0]
        self.log.info("The orphan pool keeps at most -maxorphantx orphans")
        conn = self.connect()
        orphans = [self.orphan() for _ in range(8)]
        offset = self.debug_log_size()
        for tx in orphans:
            conn.send_and_ping(msg_tx(tx))
        # The pool was empty: the 6th, 7th and 8th orphan each evict one.
        log = self.debug_log_since(offset)
        assert_equal(log.count("stored orphan tx"), 8)
        assert_equal(log.count("mapOrphan overflow, removed 1 tx"), 3)
        parents = [(MSG_TX, tx.vin[0].prevout.hash) for tx in orphans]
        wait_until(lambda: all(p in conn.getdata_requests for p in parents), timeout=10, lock=mininode_lock)

        self.log.info("Orphans from a peer are erased when it disconnects")
        with node.assert_debug_log(["Erased 5 orphan tx from peer=%d" % conn.peer_id], timeout=10):
            self.close(conn)

    def test_orphan_expiry(self):
        node = self.nodes[0]
        self.log.info("Orphans expire after 20 minutes")
        self.m8 = self.connect()
        old = self.orphan()
        with node.assert_debug_log(["stored orphan tx %s" % old.hash]):
            self.m8.send_and_ping(msg_tx(old))
        # The first orphan of the test set the next sweep to 20 min after it;
        # the clock hasn't moved since, so the next orphan after +26 min
        # sweeps, and only `old` is in the pool.
        self.set_mocktime(self.mocktime + 26 * 60)
        with node.assert_debug_log(["Erased 1 orphan tx due to expiration"]):
            self.m8.send_and_ping(msg_tx(self.orphan()))

    def test_orphan_conflicted_by_block(self):
        node = self.nodes[0]
        self.log.info("An orphan whose input a block spends is erased")
        utxo = self.next_utxo()
        orphan = CTransaction()
        orphan.nTime = self.mocktime
        orphan.vin = [CTxIn(COutPoint(utxo[0], utxo[1])), CTxIn(COutPoint(random.getrandbits(256), 0))]
        orphan.vout = [CTxOut(2 * EACH - FEE, self.k_script)]
        sign_p2pkh_input(orphan, 0, self.key)
        with node.assert_debug_log(["stored orphan tx %s" % orphan.hash]):
            self.m8.send_and_ping(msg_tx(orphan))
        node.sendrawtransaction(self.spend(utxo).serialize().hex())
        with node.assert_debug_log(["Erased 1 orphan tx included or conflicted by block"], timeout=10):
            node.generatetoaddress(1, TestNode.PRIV_KEYS[1].address)

    def test_orphan_edge_cases(self):
        node = self.nodes[0]
        self.log.info("An orphan with two missing parents gets getdata for both")
        orphan = self.orphan(n_parents=2)
        with node.assert_debug_log(["stored orphan tx %s" % orphan.hash]):
            self.m8.send_and_ping(msg_tx(orphan))
        parents = [(MSG_TX, txin.prevout.hash) for txin in orphan.vin]
        wait_until(lambda: all(p in self.m8.getdata_requests for p in parents), timeout=10, lock=mininode_lock)

        self.log.info("A second copy of an orphan isn't stored again, and nobody is punished")
        conn = self.connect()
        with node.assert_debug_log([], ["stored orphan"]):
            conn.send_and_ping(msg_tx(orphan))
        assert_equal(self.rejects(conn), [])
        assert_equal(self.banscore(conn), 0)

        self.log.info("An orphan of 100 kB or more isn't kept")
        big = self.orphan(n_outputs=3000)
        size = len(big.serialize())
        assert size >= 100000
        with node.assert_debug_log(["ignoring large orphan tx (size: %d, hash: %s)" % (size, big.hash)], ["stored orphan"]):
            conn.send_and_ping(msg_tx(big))
        assert_equal(self.rejects(conn), [])
        assert_equal(self.banscore(conn), 0)


if __name__ == '__main__':
    InvalidTxTest().main()
