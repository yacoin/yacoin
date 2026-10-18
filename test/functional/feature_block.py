#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block validity end to end, one hand-built block per reject reason.

Each block is built on the tip and submitted with submitblock, which answers
with the BIP22 string of the consensus rule the block broke; the tip must not
move. The two rules submitblock can't reach (a block that doesn't start with
a coinbase, an empty block) are sent from a mininode, which gets a reject
message. This script owns the block reject reasons for the suite; the size
and sigop limits that follow the money supply are in feature_block_limits.py.

Also: a block that failed when connecting stays invalid (duplicate-invalid,
also after a restart) and so do its children (bad-prevblk); blocks failing
the header checks leave no chain tip entry; script failures give the
specific reason with -par=1 and block-validation-failed with script check
threads.
"""

from test_framework.blocktools import (
    assert_block_accepted,
    assert_block_rejected,
    create_block_yac,
    create_coinbase_yac,
    get_template,
    mutate_merkle_mismatch,
    solve_block,
)
from test_framework.messages import (
    COIN,
    MAX_MONEY,
    REJECT_INVALID,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_block,
)
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_1, OP_CHECKSIG, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.yac_tx import key_from_wif, p2pkh_script, sign_input, sign_p2pkh_input, to_v1

FEE = COIN // 100
SCRIPT_FALSE_REASON = ("mandatory-script-verify-flag-failed (Script evaluated without error "
                       "but finished with a false/empty top stack element)")


class FeatureBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_fork_1_0 = 1
        # The specific script failure reason needs script checks on the
        # validation thread (no check queue).
        self.extra_args = [["-par=1"]]

    def run_test(self):
        self.node = self.nodes[0]
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.node.add_p2p_connection(P2PInterface())
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(self.node, 20)

        # Order matters: the premature coinbase spend needs node-mined blocks
        # at the tip, the time cases move the mocktime far ahead, and the
        # restart comes last.
        self.test_premature_coinbase()
        self.make_spendable_outputs()
        self.test_merkle_mutation()
        self.test_p2p_only_reasons()
        self.test_coinbase_rules()
        self.test_missing_inputs()
        self.test_transaction_rules()
        self.test_bad_signature()
        self.test_header_rules()
        self.test_finality()
        self.test_tx_version_and_sigops()
        self.test_invalid_parent()
        self.test_proof_of_work()
        self.test_time_far_rules()
        self.test_restart()

    # Helpers

    def next_block_time(self):
        self.set_mocktime(self.mocktime + 60)

    def reject(self, block, reason):
        solve_block(self.node, block)
        assert_block_rejected(self.node, block, reason)
        return block

    def accept(self, block):
        solve_block(self.node, block)
        assert_block_accepted(self.node, block)
        return block

    def coinbase_output(self, height):
        """(txid as int, value) of the P2PKH coinbase output of a node-mined block."""
        block = self.node.getblock(self.node.getblockhash(height), 2)
        out = block['tx'][0]['vout'][0]
        assert_equal(out['scriptPubKey']['hex'], p2pkh_script(self.pubkey).hex())
        return int(block['tx'][0]['txid'], 16), int(out['value'] * COIN)

    def signed_coinbase_spend(self, height, fee=FEE):
        """A signed spend of block height's coinbase to an OP_TRUE output."""
        txid, value = self.coinbase_output(height)
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, 0))]
        tx.vout = [CTxOut(value - fee, CScript([OP_TRUE]))]
        sign_p2pkh_input(tx, 0, self.key)
        return tx

    def tx(self, outpoints, outputs, *, ntime=None, locktime=0, sequence=0xffffffff):
        """A transaction spending OP_TRUE outputs (no signature needed)."""
        tx = CTransaction()
        tx.nTime = self.mocktime if ntime is None else ntime
        tx.nLockTime = locktime
        tx.vin = [CTxIn(COutPoint(txid, n), b"", sequence) for txid, n in outpoints]
        tx.vout = outputs
        tx.rehash()
        return tx

    def spend(self, outpoint, value=None, **kwargs):
        value = self.output_value - FEE if value is None else value
        return self.tx([outpoint], [CTxOut(value, CScript([OP_TRUE]))], **kwargs)

    def tip_entries(self, block_hash):
        return [tip['status'] for tip in self.node.getchaintips() if tip['hash'] == block_hash]

    def bad_signature_spend(self, height):
        """A spend of block height's coinbase whose signature is made over the
        wrong script code, so it never verifies."""
        txid, value = self.coinbase_output(height)
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, 0))]
        tx.vout = [CTxOut(value - FEE, CScript([OP_TRUE]))]
        tx.vin[0].scriptSig = CScript([sign_input(tx, 0, self.key, CScript([OP_TRUE])), self.pubkey])
        tx.rehash()
        return tx

    # Cases

    def test_premature_coinbase(self):
        self.log.info("A spend of a coinbase at depth 5 is premature (depth 6 is in the next block)")
        height = self.node.getblockcount() - 4
        self.next_block_time()
        self.reject(create_block_yac(self.node, [self.signed_coinbase_spend(height)]),
                    "bad-txns-premature-spend-of-coinbase/coinstake")

    def make_spendable_outputs(self):
        self.log.info("A valid block splits block 1's coinbase into OP_TRUE outputs and spends a coinbase at depth 6")
        txid, value = self.coinbase_output(1)
        fanout = CTransaction()
        fanout.nTime = self.mocktime
        fanout.vin = [CTxIn(COutPoint(txid, 0))]
        self.output_value = (value - FEE) // 40
        fanout.vout = [CTxOut(self.output_value, CScript([OP_TRUE])) for _ in range(40)]
        sign_p2pkh_input(fanout, 0, self.key)
        mature = self.signed_coinbase_spend(self.node.getblockcount() - 5)
        self.accept(create_block_yac(self.node, [fanout, mature]))
        self.fanout = fanout
        self.utxos = [(fanout.sha256, n) for n in range(40)]
        # Rejected blocks below reuse this output; it is never spent.
        self.unspent = self.utxos.pop()

    def test_merkle_mutation(self):
        self.log.info("Transactions not matching the header's merkle root: bad-txnmrklroot; the genuine block is accepted")
        self.next_block_time()
        good = solve_block(self.node, create_block_yac(self.node, [self.spend(self.utxos.pop())]))
        assert_block_rejected(self.node, mutate_merkle_mismatch(good), "bad-txnmrklroot")
        assert_block_accepted(self.node, good)

    def send_from_mininode(self, block, reason):
        peer = self.node.p2ps[0]
        peer.send_message(msg_block(block))
        peer.wait_for_reject(message=b"block", code=REJECT_INVALID, reason=reason, data=block.sha256)
        peer.wait_for_disconnect()
        self.node.disconnect_p2ps()
        self.node.add_p2p_connection(P2PInterface())

    def test_p2p_only_reasons(self):
        self.log.info("A block that doesn't start with a coinbase: submitblock refuses it, a peer gets bad-cb-missing")
        tip = self.node.getbestblockhash()
        block = create_block_yac(self.node, [self.spend(self.unspent)])
        block.vtx = block.vtx[1:]
        block.hashMerkleRoot = block.calc_merkle_root()
        solve_block(self.node, block)
        assert_raises_rpc_error(-22, "Block does not start with a coinbase", self.node.submitblock, block.serialize().hex())
        self.send_from_mininode(block, b"bad-cb-missing")

        self.log.info("An empty block: submitblock refuses it, a peer gets bad-blk-length")
        block = create_block_yac(self.node)
        block.vtx = []
        block.hashMerkleRoot = 0
        solve_block(self.node, block)
        assert_raises_rpc_error(-22, "Block does not start with a coinbase", self.node.submitblock, block.serialize().hex())
        self.send_from_mininode(block, b"bad-blk-length")
        assert_equal(self.node.getbestblockhash(), tip)

    def test_coinbase_rules(self):
        node = self.node
        tmpl = get_template(node)
        height, curtime = tmpl['height'], tmpl['curtime']

        self.log.info("A second coinbase: bad-cb-multiple")
        self.reject(create_block_yac(node, [create_coinbase_yac(height, curtime, 0)]), "bad-cb-multiple")

        self.log.info("The same transaction twice: bad-txns-duplicate")
        tx = self.spend(self.unspent)
        self.reject(create_block_yac(node, [tx, tx]), "bad-txns-duplicate")

        self.log.info("Coinbase with the wrong height: bad-cb-height")
        self.reject(create_block_yac(node, coinbase=create_coinbase_yac(height + 1, curtime, 0)), "bad-cb-height")

        self.log.info("Coinbase scriptSig of 1 byte and of 101 bytes: bad-cb-length")
        coinbase = create_coinbase_yac(height, curtime, 0)
        coinbase.vin[0].scriptSig = CScript([OP_1])
        coinbase.rehash()
        self.reject(create_block_yac(node, coinbase=coinbase), "bad-cb-length")
        coinbase = create_coinbase_yac(height, curtime, 0, extra_script=CScript([b"x" * 97]))
        assert_equal(len(coinbase.vin[0].scriptSig), 101)
        self.reject(create_block_yac(node, coinbase=coinbase), "bad-cb-length")

        self.log.info("Coinbase paying the reward plus one unit: bad-cb-amount, and the block is marked invalid")
        self.invalid_block = self.reject(create_block_yac(node, coinbase_value=tmpl['coinbasevalue'] + 1), "bad-cb-amount")
        self.invalid_height = height
        assert_equal(self.tip_entries(self.invalid_block.hash), ['invalid'])

        self.log.info("Coinbase claiming a transaction's fee: bad-cb-amount (fees are burned)")
        fee_tx = self.signed_coinbase_spend(3, fee=COIN)
        self.reject(create_block_yac(node, [fee_tx], coinbase_value=tmpl['coinbasevalue'] + COIN), "bad-cb-amount")
        self.log.info("The same transaction with the coinbase paying the reward is accepted")
        self.accept(create_block_yac(node, [fee_tx]))

    def test_missing_inputs(self):
        node = self.node
        self.log.info("A spend of a nonexistent output and a double spend in one block have no reject reason")
        # The reason Core 0.15 gives, assumed; if the fix names it differently,
        # change it here and drop the marker.
        missing = self.spend((0x1234, 0))
        block = solve_block(node, create_block_yac(node, [missing]))
        self.known_failure("C-S12 (16Ik4F0L item 2)",
                           lambda: assert_block_rejected(node, block, "bad-txns-inputs-missingorspent"),
                           "rejected == bad-txns-inputs-missingorspent")
        first = self.spend(self.unspent)
        second = self.spend(self.unspent, value=self.output_value - 2 * FEE)
        block = solve_block(node, create_block_yac(node, [first, second]))
        self.known_failure("C-S12 (16Ik4F0L item 2)",
                           lambda: assert_block_rejected(node, block, "bad-txns-inputs-missingorspent"),
                           "rejected == bad-txns-inputs-missingorspent")

    def test_transaction_rules(self):
        node = self.node
        out = self.unspent
        cases = [
            ("output above the input", self.spend(out, value=self.output_value + 1), "bad-txns-in-belowout"),
            ("output above MAX_MONEY", self.spend(out, value=MAX_MONEY + 1), "bad-txns-vout-toolarge"),
            ("negative output", self.spend(out, value=-1), "bad-txns-vout-negative"),
            ("outputs summing above MAX_MONEY",
             self.tx([out], [CTxOut(MAX_MONEY, CScript([OP_TRUE])), CTxOut(MAX_MONEY, CScript([OP_TRUE]))]),
             "bad-txns-txouttotal-toolarge"),
            ("the same input twice", self.tx([out, out], [CTxOut(self.output_value - FEE, CScript([OP_TRUE]))]),
             "bad-txns-inputs-duplicate"),
            ("no inputs", self.tx([], [CTxOut(self.output_value, CScript([OP_TRUE]))]), "bad-txns-vin-empty"),
            ("no outputs", self.tx([out], []), "bad-txns-vout-empty"),
            ("an empty output", self.tx([out], [CTxOut(0, CScript())]), "bad-txns-vout-empty"),
            ("a null prevout next to a real input",
             self.tx([out, (0, 0xffffffff)], [CTxOut(self.output_value - FEE, CScript([OP_TRUE]))]),
             "bad-txns-prevout-null"),
            ("an nTime before its input's", self.spend(out, ntime=self.fanout.nTime - 1), "bad-txns-spent-too-early"),
        ]
        for description, tx, reason in cases:
            self.log.info("A transaction with %s: %s" % (description, reason))
            self.reject(create_block_yac(node, [tx]), reason)

        self.log.info("A coinstake-shaped transaction after the second position: bad-cs-missing")
        coinstake = self.tx([out], [CTxOut(0, CScript()), CTxOut(self.output_value - FEE, CScript([OP_TRUE]))])
        self.reject(create_block_yac(node, [self.spend(self.utxos[0]), coinstake]), "bad-cs-missing")

    def test_bad_signature(self):
        self.log.info("A spend whose signature doesn't verify: the script failure reason (-par=1)")
        self.reject(create_block_yac(self.node, [self.bad_signature_spend(2)]), SCRIPT_FALSE_REASON)

    def test_header_rules(self):
        node = self.node
        tmpl = get_template(node)
        self.log.info("Wrong nBits: bad-diffbits, and no chain tip entry")
        block = self.reject(create_block_yac(node, nbits=int(tmpl['bits'], 16) - 1), "bad-diffbits")
        assert_equal(self.tip_entries(block.hash), [])
        # Header failures aren't stored, so the same block gets the same answer.
        assert_block_rejected(node, block, "bad-diffbits")

        self.log.info("Block time at the parent's median time past: time-too-old; one second later is accepted")
        mtp = node.getblockheader(node.getbestblockhash())['mediantime']
        block = self.reject(create_block_yac(node, ntime=mtp), "time-too-old")
        assert_equal(self.tip_entries(block.hash), [])
        self.accept(create_block_yac(node, ntime=mtp + 1))

        self.log.info("Block time more than 2 hours after the node's time: time-too-new; exactly 2 hours is accepted")
        self.next_block_time()
        height = node.getblockcount() + 1
        block = self.reject(create_block_yac(node, ntime=self.mocktime + 7201,
                                             coinbase=create_coinbase_yac(height, self.mocktime, 0)),
                            "time-too-new")
        assert_equal(self.tip_entries(block.hash), [])
        self.accept(create_block_yac(node, ntime=self.mocktime + 7200,
                                     coinbase=create_coinbase_yac(height, self.mocktime, 0)))
        # Continue after that block's time.
        self.set_mocktime(self.mocktime + 7260)

        self.log.info("A transaction with a later nTime than its block: bad-tx-time")
        tx = self.spend(self.unspent, ntime=self.mocktime)
        self.reject(create_block_yac(node, [tx], ntime=self.mocktime - 1), "bad-tx-time")

    def test_finality(self):
        node = self.node
        self.log.info("nLockTime at the block's height with a non-final input: bad-txns-nonfinal")
        height = node.getblockcount() + 1
        self.reject(create_block_yac(node, [self.spend(self.unspent, locktime=height, sequence=0xfffffffe)]),
                    "bad-txns-nonfinal")
        self.log.info("nLockTime one below the block's height is accepted")
        self.next_block_time()
        self.accept(create_block_yac(node, [self.spend(self.utxos.pop(), locktime=height - 1, sequence=0xfffffffe)]))
        self.log.info("nLockTime at the block's height with only final inputs is accepted")
        self.next_block_time()
        height = node.getblockcount() + 1
        self.accept(create_block_yac(node, [self.spend(self.utxos.pop(), locktime=height, sequence=0xffffffff)]))

        self.log.info("A relative lock of 2 blocks on an output 1 block deep: bad-txns-nonfinal (BIP68)")
        self.next_block_time()
        parent = self.spend(self.utxos.pop())
        self.accept(create_block_yac(node, [parent]))
        self.next_block_time()
        locked = self.spend((parent.sha256, 0), value=parent.vout[0].nValue - FEE, sequence=2)
        self.reject(create_block_yac(node, [locked]), "bad-txns-nonfinal")
        self.log.info("A relative lock of 1 block on it is accepted")
        self.accept(create_block_yac(node, [self.spend((parent.sha256, 0), value=parent.vout[0].nValue - 2 * FEE, sequence=1)]))

    def test_tx_version_and_sigops(self):
        node = self.node
        self.log.info("A version 1 transaction after the fork: bad-txns-version")
        self.next_block_time()
        self.reject(create_block_yac(node, [to_v1(self.spend(self.unspent))]), "bad-txns-version")
        self.log.info("20001 signature operations: bad-blk-sigops")
        self.reject(create_block_yac(node, script_pubkey=CScript([OP_CHECKSIG] * 20001)), "bad-blk-sigops")

    def test_invalid_parent(self):
        node = self.node
        invalid = self.invalid_block
        self.log.info("A child of the block that paid too much: bad-prevblk, and no chain tip entry")
        child = create_block_yac(node, prev=invalid, height=self.invalid_height + 1, nbits=invalid.nBits)
        self.reject(child, "bad-prevblk")
        assert_equal(self.tip_entries(child.hash), [])
        self.log.info("The invalid block again: duplicate-invalid")
        assert_equal(node.submitblock(invalid.serialize().hex()), "duplicate-invalid")

    def test_proof_of_work(self):
        node = self.node
        self.log.info("A block that doesn't meet its target, and one with nBits above the limit, have no reject reason")
        # The reason Core 0.15 gives, assumed; if the fix names it differently,
        # change it here and drop the marker.
        block = solve_block(node, create_block_yac(node), invalid=True)
        self.known_failure("R-15 (16Ik4F0L item 2)",
                           lambda: assert_block_rejected(node, block, "high-hash"),
                           "rejected == high-hash")
        block = create_block_yac(node, nbits=0x2100ffff)
        block.rehash()
        self.known_failure("R-15 (16Ik4F0L item 2)",
                           lambda: assert_block_rejected(node, block, "high-hash"),
                           "rejected == high-hash")

    def test_time_far_rules(self):
        node = self.node
        self.log.info("A block more than 2 hours before its parent: time-too-old; exactly 2 hours is accepted")
        self.set_mocktime(self.mocktime + 8000)
        self.accept(create_block_yac(node))
        height = node.getblockcount() + 1
        earlier = self.mocktime - 7201
        assert earlier > node.getblockheader(node.getbestblockhash())['mediantime']
        self.reject(create_block_yac(node, ntime=earlier, coinbase=create_coinbase_yac(height, earlier, 0)), "time-too-old")
        self.accept(create_block_yac(node, ntime=earlier + 1, coinbase=create_coinbase_yac(height, earlier + 1, 0)))

        self.log.info("A coinbase more than 2 hours after its block: bad-cb-time; exactly 2 hours gets bad-tx-time")
        self.set_mocktime(self.mocktime + 8000)
        tip_time = node.getblockheader(node.getbestblockhash())['time']
        height = node.getblockcount() + 1
        coinbase = create_coinbase_yac(height, tip_time + 7202, 0)
        assert coinbase.nTime <= self.mocktime
        self.reject(create_block_yac(node, ntime=tip_time + 1, coinbase=coinbase), "bad-cb-time")
        # Not too late for the coinbase rule, but still later than its block.
        self.reject(create_block_yac(node, ntime=tip_time + 1, coinbase=create_coinbase_yac(height, tip_time + 7201, 0)),
                    "bad-tx-time")

    def test_restart(self):
        node = self.node
        self.log.info("After a restart the block that paid too much is still invalid")
        tip = node.getbestblockhash()
        tips = sorted(node.getchaintips(), key=lambda t: t['hash'])
        self.restart_node(0)
        assert_equal(node.submitblock(self.invalid_block.serialize().hex()), "duplicate-invalid")
        assert_equal(node.getbestblockhash(), tip)
        # Same entries; tips of equal height may come back in another order.
        assert_equal(sorted(node.getchaintips(), key=lambda t: t['hash']), tips)

        self.log.info("With script check threads a script failure gives block-validation-failed")
        self.restart_node(0, extra_args=["-par=2"])
        node.add_p2p_connection(P2PInterface())
        self.next_block_time()
        self.reject(create_block_yac(node, [self.bad_signature_spend(4)]), "block-validation-failed")


if __name__ == '__main__':
    FeatureBlockTest().main()
