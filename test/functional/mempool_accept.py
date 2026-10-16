#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool acceptance: every reject reason as users see it.

YACoin has no testmempoolaccept, so each case goes through
sendrawtransaction, which answers -26 "<code>: <reason>"
(rpc/rawtransaction.cpp), and then the same transaction goes to a P2P peer,
which gets a reject message with that code and reason. The accepted
boundaries are checked too: the relay fee of 10 base units per byte, the
4000-sigop limit, the 1650-byte scriptSig, the standard output types (no
dust rule, no absurd-fee check, no RBF).

Also: a resend of a mempool transaction returns its txid, a mined one gives
-27, P2P stays silent about both; a transaction rejected over P2P once is
ignored the second time (recentRejects).

The ancestor/descendant limits (too-long-mempool-chain) are in
mempool_packages.py; CLTV/CSV and the sequence-lock boundaries in
feature_cltv_csv_enforcement.py; coinbase maturity in
mempool_spend_coinbase.py.

The peer is whitelisted, so rejects with a DoS score don't disconnect it.
Every case spends its own outpoint or pays its own amounts: v2 txids leave
out the scriptSigs, and the node drops a txid it rejected over P2P before.
"""
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    COIN,
    MAX_MONEY,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_tx,
)
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.script import (
    CScript,
    OP_1,
    OP_3,
    OP_4,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.yac_tx import (
    P2SH_TRUE_SCRIPT,
    P2SH_TRUE_SCRIPT_SIG,
    TRUE_REDEEM_SCRIPT,
    key_from_wif,
    p2pkh_script,
    p2sh_script,
    sign_p2pkh_input,
    to_v1,
)

FEE = 10000  # 0.01 YAC, plenty for the small transactions
MAX_REJECT_MESSAGE_LENGTH = 111  # net_processing.cpp


class MempoolAcceptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1"]]

    def generate_to(self, n):
        """Mine n blocks paying PRIV_KEYS[0], moving the mocktime forward."""
        for _ in range(n):
            self.set_mocktime(self.mocktime + 60)
            self.nodes[0].generatetoaddress(1, TestNode.PRIV_KEYS[0].address)

    # Building transactions

    def next_utxo(self):
        """(txid as int, n, value) of an unused P2SH_TRUE output of the funding tx."""
        return self.utxos.pop(0)

    def spend_true(self, outputs, *, utxo=None, nversion=2, ntime=None):
        """Spend one P2SH_TRUE output. outputs is a list of CTxOut or a
        function of the input value returning one."""
        txid, n, value = self.next_utxo() if utxo is None else utxo
        tx = CTransaction()
        tx.nVersion = nversion
        tx.nTime = self.mocktime if ntime is None else ntime
        tx.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG)]
        tx.vout = outputs(value) if callable(outputs) else outputs
        tx.rehash()
        return tx

    def next_coinbase(self):
        """(txid, value) of an unspent, mature coinbase paying PRIV_KEYS[0]."""
        return self.coinbases.pop(0)

    def spend_coinbase(self, outputs, *, coinbase=None, key=None):
        """Spend a coinbase of PRIV_KEYS[0], signed by key (PRIV_KEYS[0]'s by default)."""
        txid, value = self.next_coinbase() if coinbase is None else coinbase
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(txid, 16), 0))]
        tx.vout = outputs(value) if callable(outputs) else outputs
        sign_p2pkh_input(tx, 0, key or self.key, script_pubkey=self.spk)
        return tx

    # Checks

    def assert_rpc_reject(self, tx, message, code=-26):
        """sendrawtransaction fails with exactly this code and message."""
        try:
            self.nodes[0].sendrawtransaction(tx.serialize().hex())
        except JSONRPCException as e:
            assert_equal((e.error['code'], e.error['message']), (code, message))
        else:
            raise AssertionError("accepted: %s" % tx.hash)

    def check_reject(self, tx, code, reason, *, p2p=True):
        """Rejected by RPC with "<code>: <reason>" and, with p2p, by a reject
        message to the peer (reasons are cut to 111 bytes on the wire)."""
        self.assert_rpc_reject(tx, "%d: %s" % (code, reason))
        if p2p:
            self.peer.send_message(msg_tx(tx))
            self.peer.wait_for_reject(message=b"tx", code=code,
                                      reason=reason.encode()[:MAX_REJECT_MESSAGE_LENGTH],
                                      data=tx.sha256)
        assert tx.hash not in self.nodes[0].getrawmempool()

    def check_accept(self, tx):
        assert_equal(self.nodes[0].sendrawtransaction(tx.serialize().hex()), tx.hash)
        assert tx.hash in self.nodes[0].getrawmempool()

    def assert_p2p_silent(self, tx):
        """The peer sends tx and gets no reject."""
        self.peer.send_message(msg_tx(tx))
        self.peer.sync_with_ping()
        with mininode_lock:
            assert_equal(self.peer.rejects, [])

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(1600000000)
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.spk = p2pkh_script(self.pubkey)
        self.generate_to(40)
        self.coinbases = []
        for height in range(1, node.getblockcount() - 5):
            txid = node.getblock(node.getblockhash(height))['tx'][0]
            self.coinbases.append((txid, int(node.gettxout(txid, 0)['value'] * COIN)))

        self.log.info("Fund 40 anyone-can-spend P2SH outputs")
        fund = self.spend_coinbase(lambda v: [CTxOut((v - 10 * FEE) // 40, P2SH_TRUE_SCRIPT) for _ in range(40)])
        self.check_accept(fund)
        self.fund = fund
        self.utxos = [(fund.sha256, i, out.nValue) for i, out in enumerate(fund.vout)]
        self.generate_to(1)
        self.peer = node.add_p2p_connection(P2PInterface())

        self.test_accepted_and_duplicates()
        self.test_inputs()
        self.test_amounts()
        self.test_fee()
        self.test_standard()
        self.test_scripts()
        self.test_size_and_decoding()
        self.test_version_1()
        self.test_locks()
        self.test_after_mining()
        self.test_p2p_repeat()

        self.log.info("The whitelisted peer is still connected; every reject was expected")
        assert self.peer.is_connected
        with mininode_lock:
            assert_equal(self.peer.rejects, [])

    def test_accepted_and_duplicates(self):
        node = self.nodes[0]
        self.log.info("A valid transaction is accepted, with its mempool entry")
        tx = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)])
        assert_equal(len(tx.serialize()), 93)
        self.check_accept(tx)
        entry = node.getmempoolentry(tx.hash)
        assert_equal((entry['size'], entry['fee'], entry['height'], entry['time']),
                     (93, Decimal(FEE) / COIN, node.getblockcount(), self.mocktime))
        assert_equal((entry['ancestorfees'], entry['descendantfees'], entry['depends']), (FEE, FEE, []))
        info = node.getmempoolinfo()
        assert_equal((info['size'], info['bytes']), (1, 93))
        self.valid_tx = tx

        self.log.info("Sending it again returns the txid; P2P stays silent")
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.hash)
        self.assert_p2p_silent(tx)

        self.log.info("Spending the same input again: txn-mempool-conflict")
        conflict = CTransaction(tx)
        conflict.vout[0].nValue -= 1
        conflict.rehash()
        self.check_reject(conflict, 18, "txn-mempool-conflict")

    def test_inputs(self):
        node = self.nodes[0]
        self.log.info("An unknown input: Missing inputs; over P2P an orphan, no reject")
        missing = CTransaction()
        missing.nTime = self.mocktime
        missing.vin = [CTxIn(COutPoint(0x1234, 0), P2SH_TRUE_SCRIPT_SIG)]
        missing.vout = [CTxOut(COIN, P2SH_TRUE_SCRIPT)]
        missing.rehash()
        self.assert_rpc_reject(missing, "Missing inputs", code=-25)
        self.assert_p2p_silent(missing)

        self.log.info("Coinbase-shaped transactions: coinbase, bad-cb-length")
        coinbase = CTransaction()
        coinbase.nTime = self.mocktime
        coinbase.vin = [CTxIn(COutPoint(0, 0xffffffff), b"\x01\x02")]
        coinbase.vout = [CTxOut(COIN, P2SH_TRUE_SCRIPT)]
        coinbase.rehash()
        self.check_reject(coinbase, 16, "coinbase")
        coinbase.vin[0].scriptSig = b"\x01"
        coinbase.vout[0].nValue += 1
        coinbase.rehash()
        self.check_reject(coinbase, 16, "bad-cb-length", p2p=False)
        self.log.info("A real coinbase is already in the chain (its outputs are unspent)")
        real = node.getblock(node.getblockhash(3))['tx'][0]
        assert_raises_rpc_error(-27, "transaction already in block chain",
                                node.sendrawtransaction, node.getrawtransaction(real))

        self.log.info("Coinstake-shaped (first output empty): coinstake")
        coinstake = self.spend_true(lambda v: [CTxOut(0, CScript()), CTxOut(v - FEE, P2SH_TRUE_SCRIPT)])
        self.check_reject(coinstake, 16, "coinstake")

        self.log.info("Duplicate inputs, null prevout, no inputs")
        txid, n, value = self.next_utxo()
        dup = CTransaction()
        dup.nTime = self.mocktime
        dup.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG)] * 2
        dup.vout = [CTxOut(value, P2SH_TRUE_SCRIPT)]
        dup.rehash()
        self.check_reject(dup, 16, "bad-txns-inputs-duplicate")
        dup.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG), CTxIn(COutPoint(0, 0xffffffff), P2SH_TRUE_SCRIPT_SIG)]
        dup.rehash()
        self.check_reject(dup, 16, "bad-txns-prevout-null")
        empty = CTransaction()
        empty.nTime = self.mocktime
        empty.vout = [CTxOut(COIN, P2SH_TRUE_SCRIPT)]
        empty.rehash()
        self.check_reject(empty, 16, "bad-txns-vin-empty")

        self.log.info("Spending the tip's coinbase: premature spend")
        tip_coinbase = node.getblock(node.getbestblockhash())['tx'][0]
        value = int(node.gettxout(tip_coinbase, 0)['value'] * COIN)
        premature = self.spend_coinbase(lambda v: [CTxOut(v - FEE, self.spk)], coinbase=(tip_coinbase, value))
        self.check_reject(premature, 16, "bad-txns-premature-spend-of-coinbase/coinstake")

        self.log.info("nTime before the input's nTime: bad-txns-spent-too-early; equal is fine")
        utxo = self.next_utxo()
        early = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)], utxo=utxo, ntime=self.fund.nTime - 1)
        self.check_reject(early, 16, "bad-txns-spent-too-early")
        self.check_accept(self.spend_true(lambda v: [CTxOut(v - FEE - 1, P2SH_TRUE_SCRIPT)], utxo=utxo, ntime=self.fund.nTime))

    def test_amounts(self):
        self.log.info("No outputs, or a zero-value output with an empty script: bad-txns-vout-empty")
        self.check_reject(self.spend_true([]), 16, "bad-txns-vout-empty")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT), CTxOut(0, CScript())]),
                          16, "bad-txns-vout-empty")

        self.log.info("Negative, too large, too large in total; more out than in")
        utxo = self.next_utxo()
        self.check_reject(self.spend_true(lambda v: [CTxOut(-1, P2SH_TRUE_SCRIPT), CTxOut(v - FEE, P2SH_TRUE_SCRIPT)], utxo=utxo),
                          16, "bad-txns-vout-negative")
        self.check_reject(self.spend_true([CTxOut(MAX_MONEY + 1, P2SH_TRUE_SCRIPT)], utxo=utxo),
                          16, "bad-txns-vout-toolarge")
        self.check_reject(self.spend_true([CTxOut(MAX_MONEY, P2SH_TRUE_SCRIPT)] * 2, utxo=utxo),
                          16, "bad-txns-txouttotal-toolarge")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v + 1, P2SH_TRUE_SCRIPT)], utxo=utxo),
                          16, "bad-txns-in-belowout")

    def test_fee(self):
        node = self.nodes[0]
        self.log.info("Relay fee boundary: 10 base units per byte (930 for 93 bytes)")
        utxo = self.next_utxo()
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - 929, P2SH_TRUE_SCRIPT)], utxo=utxo),
                          66, "mempool min fee not met")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v, P2SH_TRUE_SCRIPT)], utxo=utxo),
                          66, "mempool min fee not met")
        tx = self.spend_true(lambda v: [CTxOut(v - 930, P2SH_TRUE_SCRIPT)], utxo=utxo)
        self.check_accept(tx)
        assert_equal(node.getmempoolentry(tx.hash)['fee'], Decimal(930) / COIN)

        self.log.info("No cap on high fees: the whole input as fee, one zero-value OP_RETURN")
        self.check_accept(self.spend_true([CTxOut(0, CScript([OP_RETURN]))]))

    def test_standard(self):
        self.log.info("Versions 3, 0 and -1: version")
        utxo = self.next_utxo()
        for version in (3, 0, -1):
            tx = self.spend_true(lambda v: [CTxOut(v - FEE - version, P2SH_TRUE_SCRIPT)], utxo=utxo, nversion=version)
            self.check_reject(tx, 64, "version")

        self.log.info("scriptSig of 1650 bytes is accepted, 1651 bytes: scriptsig-size")
        utxo = self.next_utxo()
        for last_push, accepted in ((77, True), (78, False)):
            # Pushes of at most 520 bytes (the script element limit) and the
            # redeem script; extra stack items are fine for this P2SH input.
            tx = self.spend_true(lambda v: [CTxOut(v - 2 * FEE - last_push, P2SH_TRUE_SCRIPT)], utxo=utxo)
            tx.vin[0].scriptSig = CScript([b"\x00" * 520] * 3 + [b"\x00" * last_push, bytes(TRUE_REDEEM_SCRIPT)])
            tx.rehash()
            assert_equal(len(tx.vin[0].scriptSig), 1650 if accepted else 1651)
            if accepted:
                self.check_accept(tx)
            else:
                self.check_reject(tx, 64, "scriptsig-size")

        self.log.info("scriptSig with OP_DUP: scriptsig-not-pushonly")
        tx = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)])
        tx.vin[0].scriptSig = CScript([OP_TRUE, OP_DUP, OP_DROP, bytes(TRUE_REDEEM_SCRIPT)])
        tx.rehash()
        self.check_reject(tx, 64, "scriptsig-not-pushonly")

        self.log.info("Non-standard outputs: scriptpubkey, multi-op-return, txout-value=0")
        pk = self.pubkey
        utxo = self.next_utxo()
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - FEE, CScript([OP_TRUE]))], utxo=utxo),
                          64, "scriptpubkey")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - FEE, CScript([OP_1, pk, pk, pk, pk, OP_4, OP_CHECKMULTISIG]))], utxo=utxo),
                          64, "scriptpubkey")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT),
                                                     CTxOut(0, CScript([OP_RETURN, b"a"])),
                                                     CTxOut(0, CScript([OP_RETURN, b"b"]))], utxo=utxo),
                          64, "multi-op-return")
        self.check_reject(self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT), CTxOut(0, self.spk)], utxo=utxo),
                          64, "txout-value=0")

        self.log.info("Standard outputs: bare 1-of-3, bare P2PK, a 1-unit P2PKH (no dust rule), a 5000-byte OP_RETURN")
        tx = self.spend_true(lambda v: [CTxOut(1, CScript([OP_1, pk, pk, pk, OP_3, OP_CHECKMULTISIG])),
                                        CTxOut(1, CScript([pk, OP_CHECKSIG])),
                                        CTxOut(1, self.spk),
                                        CTxOut(0, CScript([OP_RETURN, b"a" * 5000])),
                                        CTxOut(v - 3 - 6 * FEE, P2SH_TRUE_SCRIPT)])
        self.check_accept(tx)

        self.log.info("Non-standard inputs: a P2PKH scriptSig with an extra push")
        tx = self.spend_coinbase(lambda v: [CTxOut(v - FEE, self.spk)])
        tx.vin[0].scriptSig = CScript([b"\x01"] + list(tx.vin[0].scriptSig))
        tx.rehash()
        self.check_reject(tx, 64, "bad-txns-nonstandard-inputs")

        self.log.info("A P2SH redeem script with 22 sigops is non-standard; 21 passes and runs")
        redeem22 = CScript([OP_CHECKSIG] * 22 + [OP_TRUE])
        redeem21 = CScript([OP_CHECKSIG] * 21 + [OP_TRUE])
        parent = self.spend_true(lambda v: [CTxOut((v - FEE) // 2, p2sh_script(redeem22)),
                                            CTxOut((v - FEE) // 2, p2sh_script(redeem21))])
        self.check_accept(parent)
        for i, (redeem, code, reason) in enumerate((
                (redeem22, 64, "bad-txns-nonstandard-inputs"),
                (redeem21, 16, "mandatory-script-verify-flag-failed (Operation not valid with the current stack size)"))):
            tx = self.spend_true([CTxOut(parent.vout[i].nValue - FEE, P2SH_TRUE_SCRIPT)],
                                 utxo=(parent.sha256, i, parent.vout[i].nValue))
            tx.vin[0].scriptSig = CScript([bytes(redeem)])
            tx.rehash()
            self.check_reject(tx, code, reason)

        self.log.info("A non-standard input after a P2SH input isn't checked (known failure)")
        txid, n, value = self.next_utxo()
        cb_txid, cb_value = self.next_coinbase()
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG), CTxIn(COutPoint(int(cb_txid, 16), 0))]
        tx.vout = [CTxOut(value + cb_value - FEE, self.spk)]
        sign_p2pkh_input(tx, 1, self.key)
        tx.vin[1].scriptSig = CScript([b"\x01"] + list(tx.vin[1].scriptSig))
        tx.rehash()
        # AreInputsStandard returns after the first P2SH input whose redeem
        # script isn't a template (policy.cpp), so the second input passes.
        # Today the transaction is accepted (and mined later).
        self.known_failure("AreInputsStandard (vYIT3MDQ)",
                           lambda: self.assert_rpc_reject(tx, "64: bad-txns-nonstandard-inputs"),
                           "accepted: ")

        self.log.info("Sigop limit 4000 (legacy count, outputs included): 4001 rejected, 4000 accepted")
        coinbase = self.next_coinbase()
        multisig = CScript([OP_1, self.pubkey, self.pubkey, self.pubkey, OP_3, OP_CHECKMULTISIG])
        for p2pkh_outputs, accepted in ((21, False), (20, True)):
            # 199 bare multisig outputs count 20 sigops each, P2PKH outputs 1.
            outputs = lambda v: ([CTxOut(1, multisig)] * 199 + [CTxOut(1, self.spk)] * (p2pkh_outputs - 1) +
                                 [CTxOut(v - 199 - p2pkh_outputs - 30 * FEE, self.spk)])
            tx = self.spend_coinbase(outputs, coinbase=coinbase)
            if accepted:
                self.check_accept(tx)
            else:
                self.check_reject(tx, 64, "bad-txns-too-many-sigops")

    def test_scripts(self):
        self.log.info("Signed by the wrong key: mandatory-script-verify-flag-failed")
        tx = self.spend_coinbase(lambda v: [CTxOut(v - FEE, self.spk)], key=key_from_wif(TestNode.PRIV_KEYS[1].key))
        self.check_reject(tx, 16, "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)")

        self.log.info("A P2SH spend pushing the wrong redeem script: false top stack element")
        tx = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)])
        tx.vin[0].scriptSig = CScript([b""])
        tx.rehash()
        self.check_reject(tx, 16, "mandatory-script-verify-flag-failed (Script evaluated without error "
                                  "but finished with a false/empty top stack element)")

    def test_size_and_decoding(self):
        node = self.nodes[0]
        self.log.info("Larger than the maximum block size (about 380 kB here): bad-txns-oversize")
        tx = self.spend_coinbase(lambda v: [CTxOut(1, P2SH_TRUE_SCRIPT)] * 12500)
        assert len(tx.serialize()) > 400000
        self.check_reject(tx, 16, "bad-txns-oversize", p2p=False)

        self.log.info("Undecodable hex: TX decode failed")
        for bad_hex in ("", "00", "zz"):
            assert_raises_rpc_error(-22, "TX decode failed", node.sendrawtransaction, bad_hex)

        self.log.info("Trailing bytes and invalid output scripts decode (known failure)")
        valid_hex = self.valid_tx.serialize().hex()
        self.known_failure("DecodeHexTx (QDofTzi1)",
                           lambda: assert_raises_rpc_error(-22, "TX decode failed", node.decoderawtransaction, valid_hex + "00"),
                           "No exception raised")
        tx = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT), CTxOut(1, CScript(b"\xff\xff"))])
        self.known_failure("DecodeHexTx (QDofTzi1)",
                           lambda: assert_raises_rpc_error(-22, "TX decode failed", node.sendrawtransaction, tx.serialize().hex()),
                           "Unexpected JSONRPC error code -26")

    def test_version_1(self):
        self.log.info("A version 1 transaction after the fork (known failure: no reason, no P2P reject)")
        v1 = to_v1(self.spend_coinbase(lambda v: [CTxOut(v - FEE, self.spk)]))
        sign_p2pkh_input(v1, 0, self.key)
        self.known_failure("C-S2 (MbqE60TC item 2)",
                           lambda: self.assert_rpc_reject(v1, "16: bad-txns-version"),
                           "(-25, '')")
        self.peer.send_message(msg_tx(v1))
        self.peer.sync_with_ping()

        def check_p2p_reject():
            with mininode_lock:
                assert_equal([r.reason for r in self.peer.rejects], [b"bad-txns-version"])
        self.known_failure("C-S2 (MbqE60TC item 2), P2P", check_p2p_reject, "not([] == [b'bad-txns-version'])")

    def test_locks(self):
        node = self.nodes[0]
        self.log.info("nLockTime tip + 1: non-final; tip is accepted")
        tip = node.getblockcount()
        utxo = self.next_utxo()
        for locktime, accepted in ((tip + 1, False), (tip, True)):
            tx = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)], utxo=utxo)
            tx.nLockTime = locktime
            tx.vin[0].nSequence = 0xfffffffe
            tx.rehash()
            if accepted:
                self.check_accept(tx)
            else:
                self.check_reject(tx, 64, "non-final")

        self.log.info("A sequence lock not met yet: non-BIP68-final")
        parent = self.spend_true(lambda v: [CTxOut((v - FEE) // 2, P2SH_TRUE_SCRIPT)] * 2)
        self.check_accept(parent)
        # A parent and a child for test_after_mining: mined together, so the
        # parent's only output is spent.
        self.spent_parent = self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)])
        self.check_accept(self.spent_parent)
        self.check_accept(self.spend_true(lambda v: [CTxOut(v - FEE, P2SH_TRUE_SCRIPT)],
                                          utxo=(self.spent_parent.sha256, 0, self.spent_parent.vout[0].nValue)))
        # This block mines everything accepted so far (and resets the P2P
        # rejects filter).
        self.generate_to(1)
        assert_equal(node.getrawmempool(), [])
        for i, (sequence, accepted) in enumerate(((2, False), (1, True))):
            tx = self.spend_true([CTxOut(parent.vout[i].nValue - FEE, P2SH_TRUE_SCRIPT)],
                                 utxo=(parent.sha256, i, parent.vout[i].nValue))
            tx.vin[0].nSequence = sequence
            tx.rehash()
            if accepted:
                self.check_accept(tx)
            else:
                self.check_reject(tx, 64, "non-BIP68-final")

    def test_after_mining(self):
        node = self.nodes[0]
        self.log.info("A mined transaction: -27 by RPC, silence over P2P")
        assert_raises_rpc_error(-27, "transaction already in block chain",
                                node.sendrawtransaction, self.valid_tx.serialize().hex())
        self.assert_p2p_silent(self.valid_tx)
        self.log.info("A mined transaction whose outputs are all spent: Missing inputs")
        assert_raises_rpc_error(-25, "Missing inputs", node.sendrawtransaction, self.spent_parent.serialize().hex())

    def test_p2p_repeat(self):
        node = self.nodes[0]
        self.log.info("Rejected over P2P once, ignored the second time; the RPC still says why")
        tx = self.spend_true(lambda v: [CTxOut(v - 929, P2SH_TRUE_SCRIPT)])
        self.check_reject(tx, 66, "mempool min fee not met")
        self.assert_p2p_silent(tx)
        self.assert_rpc_reject(tx, "66: mempool min fee not met")
        assert_equal(node.getmempoolinfo()['size'], 1)  # the sequence-lock spend


if __name__ == '__main__':
    MempoolAcceptTest().main()
