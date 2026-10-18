#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descendant package tracking code and the mempool RPCs.

Port of Bitcoin Core 0.15's mempool_packages.py. YACoin's limits are fixed:
25 ancestors, 25 descendants and 101,000 bytes each way (txmempool.h); the
-limitancestorcount/-limitdescendantcount/... options don't exist (they are
ignored like any unknown option), so Core's second node with lower limits
and the prioritisetransaction parts are left out. Fees are 0.01 YAC for the
small transactions and the minimum (10 base units per byte) for the large
ones.

Checks:
- a chain of 25: every getmempoolentry field, getmempoolancestors,
  getmempooldescendants (verbose and not), getrawmempool and getmempoolinfo;
  the 26th is refused;
- each limit at its exact boundary, with the reason the node logs: ancestor
  count, descendant count, parent count, ancestor size, descendant size;
- a block that confirms the start of the chain recomputes the rest
  (removeForBlock), and disconnecting it puts the transactions back and
  links them again (UpdateTransactionsFromBlock), even past the limit;
- a disconnect that brings back more than the limit allows keeps the first
  25 and drops the rest;
- the RPCs' errors for unknown and malformed txids.

Most transactions spend anyone-can-spend P2SH outputs (yac_tx.P2SH_TRUE_*),
so their sizes are exact. The large transactions are padded with 1-unit
outputs, not one huge OP_RETURN: output scripts over 10,000 bytes
(MAX_SCRIPT_SIZE) are meant to fail decoding.
"""
from decimal import Decimal

from test_framework.blocktools import assert_block_accepted, create_block_yac, solve_block
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, FromHex, msg_tx
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, satoshi_round
from test_framework.yac_tx import P2SH_TRUE_SCRIPT, P2SH_TRUE_SCRIPT_SIG

MAX_ANCESTORS = 25
MAX_DESCENDANTS = 25
MAX_PACKAGE_SIZE = 101000  # bytes, ancestors and descendants (DEFAULT_*_SIZE_LIMIT * 1000)
FEE = 10000  # 0.01 YAC in base units


class MempoolPackagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    # Build/send a transaction with the wallet (Core's helper; the chain uses one output).
    def chain_transaction(self, node, parent_txid, vout, value, fee, num_outputs, *, send=True):
        send_value = satoshi_round((value - fee) / num_outputs)
        inputs = [{'txid': parent_txid, 'vout': vout}]
        outputs = {}
        for _ in range(num_outputs):
            outputs[node.getnewaddress()] = send_value
        rawtx = node.createrawtransaction(inputs, outputs)
        signedtx = node.signrawtransaction(rawtx)
        assert signedtx['complete']
        if not send:
            return signedtx['hex']
        txid = node.sendrawtransaction(signedtx['hex'])
        fulltx = node.getrawtransaction(txid, 1)
        assert_equal(len(fulltx['vout']), num_outputs)  # no change output
        return (txid, send_value)

    # Python transactions spending P2SH_TRUE outputs.
    def spend(self, prevouts, outputs, fee=FEE):
        """prevouts: [(txid int, n, value)]; outputs: number of equal
        P2SH_TRUE outputs sharing the inputs minus fee."""
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(txid, n), P2SH_TRUE_SCRIPT_SIG) for txid, n, _ in prevouts]
        total = sum(value for _, _, value in prevouts) - fee
        tx.vout = [CTxOut(total // outputs, P2SH_TRUE_SCRIPT) for _ in range(outputs)]
        tx.rehash()
        return tx

    def big_spend(self, prevouts, size, outputs=1):
        """A spend of exactly size bytes paying the minimum fee (10 base units
        per byte), padded with 1-unit outputs and one short OP_RETURN."""
        tx = self.spend(prevouts, outputs, fee=0)
        # 32 bytes per 1-unit output; leave 38 to 72 bytes for the OP_RETURN.
        padding = max(0, (size - len(tx.serialize()) - 40) // 32)
        tx.vout += [CTxOut(1, P2SH_TRUE_SCRIPT) for _ in range(padding)]
        # An OP_RETURN output with d data bytes (d <= 75) takes 11 + d bytes.
        data = size - len(tx.serialize()) - 11
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b"x" * data])))
        data -= len(tx.serialize()) - size  # the output count may have grown a byte or two
        tx.vout[-1] = CTxOut(0, CScript([OP_RETURN, b"x" * data]))
        assert_equal(len(tx.serialize()), size)
        padding = len(tx.vout) - outputs - 1
        value = (sum(v for _, _, v in prevouts) - size * 10 - padding) // outputs
        for out in tx.vout[:outputs]:
            out.nValue = value
        tx.rehash()
        return tx

    def outs(self, tx, n=None):
        """The (txid, n, value) of tx's first n outputs (all value outputs by default)."""
        found = [(tx.sha256, i, out.nValue) for i, out in enumerate(tx.vout) if out.nValue > 1]
        return found if n is None else found[:n]

    def send(self, tx):
        assert_equal(self.nodes[0].sendrawtransaction(tx.serialize().hex()), tx.hash)

    def assert_too_long(self, tx, log_reason):
        """Refused by RPC, and over P2P with log_reason in the debug log."""
        node = self.nodes[0]
        assert_raises_rpc_error(-26, "64: too-long-mempool-chain", node.sendrawtransaction, tx.serialize().hex())
        with node.assert_debug_log([log_reason]):
            self.peer.send_message(msg_tx(tx))
            self.peer.wait_for_reject(message=b"tx", code=64, reason=b"too-long-mempool-chain", data=tx.sha256)
        assert tx.hash not in node.getrawmempool()

    def fund(self, outputs):
        """Spend one wallet coinbase to `outputs` P2SH_TRUE outputs (signed by the wallet)."""
        node = self.nodes[0]
        coin = self.coins.pop()
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coin['txid'], 16), coin['vout']))]
        value = int(coin['amount'] * COIN) - 10 * FEE
        tx.vout = [CTxOut(value // outputs, P2SH_TRUE_SCRIPT) for _ in range(outputs)]
        signed = node.signrawtransaction(tx.serialize().hex())
        assert signed['complete']
        tx = FromHex(CTransaction(), signed['hex'])
        tx.rehash()
        self.send(tx)
        return self.outs(tx)

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(node, 40, sync=False)
        # The peer receives the P2P rejects; getblocktemplate needs a peer too.
        self.peer = node.add_p2p_connection(P2PInterface())
        self.coins = sorted((u for u in node.listunspent() if u['amount'] > 1), key=lambda u: u['txid'])

        f_fan = self.fund(1)
        f_parents = self.fund(25)
        f_big = [self.fund(1)[0] for _ in range(6)]
        f_reorg = self.fund(1)
        self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getrawmempool(), [])

        self.test_chain()
        self.test_descendant_count(f_fan)
        self.test_parent_count(f_parents)
        self.test_size_limits(f_big)
        self.test_block_and_disconnect()
        self.test_disconnect_over_limit(f_reorg)
        self.test_rpc_errors()

    def test_chain(self):
        node = self.nodes[0]
        self.log.info("A chain of %d transactions and the mempool RPCs" % MAX_ANCESTORS)
        utxo = self.coins.pop()
        txid, vout, value = utxo['txid'], utxo['vout'], utxo['amount']
        fee = Decimal("0.01")
        chain = []
        for _ in range(MAX_ANCESTORS):
            (txid, sent_value) = self.chain_transaction(node, txid, vout, value, fee, 1)
            value = sent_value
            vout = 0
            chain.append(txid)
        self.chain = chain
        self.chain_tip = (txid, value)

        mempool = node.getrawmempool(True)
        sizes = [mempool[t]['size'] for t in chain]
        for t in chain:
            assert_equal(mempool[t]['size'], len(node.getrawtransaction(t)) // 2)
        fees = [FEE] * MAX_ANCESTORS
        for i, t in enumerate(chain):
            entry = node.getmempoolentry(t)
            assert_equal(entry, mempool[t])
            assert_equal((entry['ancestorcount'], entry['ancestorsize'], entry['ancestorfees']),
                         (i + 1, sum(sizes[:i + 1]), sum(fees[:i + 1])))
            assert_equal((entry['descendantcount'], entry['descendantsize'], entry['descendantfees']),
                         (MAX_ANCESTORS - i, sum(sizes[i:]), sum(fees[i:])))
            assert_equal((entry['fee'], entry['height'], entry['time']),
                         (fee, node.getblockcount(), self.mocktime))
            assert_equal(entry['depends'], [chain[i - 1]] if i else [])
            # The RPCs order by uint256, not by hex string: compare sorted.
            assert_equal(sorted(node.getmempoolancestors(t)), sorted(chain[:i]))
            assert_equal(node.getmempoolancestors(t, True), {a: mempool[a] for a in chain[:i]})
            assert_equal(sorted(node.getmempooldescendants(t)), sorted(chain[i + 1:]))
            assert_equal(node.getmempooldescendants(t, True), {d: mempool[d] for d in chain[i + 1:]})

        info = node.getmempoolinfo()
        assert_equal(sorted(info.keys()), ["bytes", "maxmempool", "size", "usage"])
        assert_equal((info['size'], info['bytes']), (MAX_ANCESTORS, sum(sizes)))
        assert info['usage'] > 0
        assert_equal(sorted(node.getrawmempool()), sorted(chain))

        self.log.info("The 26th is refused: too many unconfirmed ancestors")
        rawtx = self.chain_transaction(node, txid, 0, value, fee, 1, send=False)
        tx = FromHex(CTransaction(), rawtx)
        tx.rehash()
        self.assert_too_long(tx, "too many unconfirmed ancestors [limit: %d]" % MAX_ANCESTORS)

    def test_descendant_count(self, f_fan):
        node = self.nodes[0]
        self.log.info("A parent with %d descendants (itself included); one more is refused" % MAX_DESCENDANTS)
        parent = self.spend(f_fan, 30, fee=2 * FEE)
        assert_equal(len(parent.serialize()), 1021)
        self.send(parent)
        parent_fee = f_fan[0][2] - sum(out.nValue for out in parent.vout)  # 2 * FEE plus the rounding
        outputs = self.outs(parent)
        children = [self.spend([outputs[i]], 1) for i in range(MAX_DESCENDANTS - 1)]
        for child in children:
            self.send(child)
        entry = node.getmempoolentry(parent.hash)
        assert_equal((entry['descendantcount'], entry['descendantsize'], entry['descendantfees']),
                     (MAX_DESCENDANTS, 1021 + 24 * 93, parent_fee + 24 * FEE))
        assert_equal(sorted(node.getmempooldescendants(parent.hash)), sorted(c.hash for c in children))
        child_entry = node.getmempoolentry(children[0].hash)
        assert_equal((child_entry['ancestorcount'], child_entry['ancestorsize'], child_entry['depends']),
                     (2, 1021 + 93, [parent.hash]))
        self.assert_too_long(self.spend([outputs[MAX_DESCENDANTS - 1]], 1),
                             "too many descendants for tx %s [limit: %d]" % (parent.hash, MAX_DESCENDANTS))

    def test_parent_count(self, f_parents):
        node = self.nodes[0]
        self.log.info("24 in-mempool parents are fine, 25 are refused")
        parents = [self.spend([f], 2) for f in f_parents]
        for p in parents:
            self.send(p)
        parent_size = len(parents[0].serialize())
        child = self.spend([self.outs(p)[0] for p in parents[:24]], 1, fee=4 * FEE)
        self.send(child)
        entry = node.getmempoolentry(child.hash)
        assert_equal((entry['ancestorcount'], entry['ancestorsize'], entry['depends']),
                     (25, len(child.serialize()) + 24 * parent_size, sorted(p.hash for p in parents[:24])))
        self.assert_too_long(self.spend([self.outs(p)[1] for p in parents], 1, fee=4 * FEE),
                             "too many unconfirmed parents [limit: %d]" % MAX_ANCESTORS)

    def test_size_limits(self, f_big):
        node = self.nodes[0]
        self.log.info("Ancestor size: exactly %d bytes is fine, one more byte is refused" % MAX_PACKAGE_SIZE)
        # Two parents: with one, the parent's descendant size check fires first.
        child_size = len(self.spend([f_big[0], f_big[1]], 1).serialize())
        assert_equal(child_size, 136)
        for (a, b), extra in (((f_big[0], f_big[1]), 0), ((f_big[2], f_big[3]), 1)):
            parent_a = self.big_spend([a], 50000)
            parent_b = self.big_spend([b], MAX_PACKAGE_SIZE - 50000 - child_size + extra)
            self.send(parent_a)
            self.send(parent_b)
            child = self.spend([self.outs(parent_a)[0], self.outs(parent_b)[0]], 1)
            if extra:
                self.assert_too_long(child, "exceeds ancestor size limit [limit: %d]" % MAX_PACKAGE_SIZE)
            else:
                self.send(child)
                entry = node.getmempoolentry(child.hash)
                assert_equal((entry['ancestorcount'], entry['ancestorsize']), (3, MAX_PACKAGE_SIZE))

        self.log.info("Descendant size: exactly %d bytes is fine, one more byte is refused" % MAX_PACKAGE_SIZE)
        for f, extra in ((f_big[4], 0), (f_big[5], 1)):
            parent = self.big_spend([f], 60000)
            self.send(parent)
            child = self.big_spend(self.outs(parent, 1), MAX_PACKAGE_SIZE - 60000 + extra)
            if extra:
                self.assert_too_long(child, "exceeds descendant size limit for tx %s [limit: %d]" % (parent.hash, MAX_PACKAGE_SIZE))
            else:
                self.send(child)
                assert_equal(node.getmempoolentry(parent.hash)['descendantsize'], MAX_PACKAGE_SIZE)
                assert_equal(node.getmempoolentry(child.hash)['ancestorsize'], MAX_PACKAGE_SIZE)

    def test_block_and_disconnect(self):
        node = self.nodes[0]
        chain = self.chain
        self.log.info("A block with the first 10 of the chain: the other 15 are recomputed")
        sizes = [node.getmempoolentry(t)['size'] for t in chain]
        before = node.getmempoolinfo()['size']
        self.set_mocktime(self.mocktime + 60)
        block = create_block_yac(node, [FromHex(CTransaction(), node.getrawtransaction(t)) for t in chain[:10]])
        solve_block(node, block)
        assert_block_accepted(node, block)
        assert_equal(node.getmempoolinfo()['size'], before - 10)
        for t in chain[:10]:
            assert_raises_rpc_error(-5, "Transaction not in mempool", node.getmempoolentry, t)
        for j in range(10, 25):
            entry = node.getmempoolentry(chain[j])
            assert_equal((entry['ancestorcount'], entry['ancestorsize'], entry['descendantcount']),
                         (j - 9, sum(sizes[10:j + 1]), 25 - j))
        assert_equal(node.getmempoolentry(chain[10])['depends'], [])

        self.log.info("Extend the chain to 25 in the mempool again; the next one is refused")
        txid, value = self.chain_tip
        fee = Decimal("0.01")
        for _ in range(10):
            (txid, value) = self.chain_transaction(node, txid, 0, value, fee, 1)
            chain.append(txid)
            sizes.append(node.getmempoolentry(txid)['size'])
        rawtx = self.chain_transaction(node, txid, 0, value, fee, 1, send=False)
        assert_raises_rpc_error(-26, "64: too-long-mempool-chain", node.sendrawtransaction, rawtx)

        self.log.info("Disconnecting the block brings the 10 back: a chain of 35")
        # Like Core, the limits aren't applied to transactions coming back
        # from a disconnected block before their mempool children are linked.
        node.invalidateblock(block.hash)
        assert_equal(node.getbestblockhash(), "%064x" % block.hashPrevBlock)
        mempool = node.getrawmempool()
        assert all(t in mempool for t in chain)
        first, last = node.getmempoolentry(chain[0]), node.getmempoolentry(chain[34])
        assert_equal((first['descendantcount'], first['descendantsize'], first['height']),
                     (35, sum(sizes), node.getblockcount()))
        assert_equal((last['ancestorcount'], last['ancestorsize']), (35, sum(sizes)))
        assert_raises_rpc_error(-26, "64: too-long-mempool-chain", node.sendrawtransaction, rawtx)

    def test_disconnect_over_limit(self, f_reorg):
        node = self.nodes[0]
        self.log.info("Mine everything")
        for _ in range(5):
            if not node.getrawmempool():
                break
            self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getrawmempool(), [])

        self.log.info("Two blocks with a chain of 25 each, a child of the last in the mempool")
        prev, txs = f_reorg, []
        for _ in range(50):
            tx = self.spend(prev, 1)
            self.send(tx)
            txs.append(tx)
            prev = self.outs(tx)
            if len(txs) == 25:
                block_a = self.mine_with_mocktime(node, 1, sync=False)[0]
                assert_equal(len(node.getblock(block_a)['tx']), 26)
        self.mine_with_mocktime(node, 1, sync=False)
        child = self.spend(prev, 1)
        self.send(child)

        self.log.info("Disconnecting both: the first 25 come back, the rest is dropped")
        # The 26th has 25 in-mempool ancestors again and is refused; the
        # later ones miss their inputs, which drops the child too.
        node.invalidateblock(block_a)
        assert_equal(node.getbestblockhash(), node.getblockheader(block_a)['previousblockhash'])
        assert_equal(sorted(node.getrawmempool()), sorted(tx.hash for tx in txs[:25]))
        assert_equal(node.getmempoolentry(txs[24].hash)['ancestorcount'], 25)
        self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getrawmempool(), [])
        info = node.getmempoolinfo()
        assert_equal((info['size'], info['bytes']), (0, 0))

    def test_rpc_errors(self):
        node = self.nodes[0]
        self.log.info("getmempoolentry/ancestors/descendants errors")
        for rpc in (node.getmempoolentry, node.getmempoolancestors, node.getmempooldescendants):
            assert_raises_rpc_error(-5, "Transaction not in mempool", rpc, "00" * 32)
            assert_raises_rpc_error(-5, "Transaction not in mempool", rpc, self.chain[0])  # mined
            assert_raises_rpc_error(-8, "parameter 1 must be of length 64 (not 4)", rpc, "abcd")
            assert_raises_rpc_error(-8, "parameter 1 must be hexadecimal string (not '%s')" % ("zz" * 32), rpc, "zz" * 32)
            assert_raises_rpc_error(-8, "parameter 1 must be hexadecimal string (not 'abc')", rpc, "abc")
        assert_raises_rpc_error(-1, "getmempoolancestors txid (verbose)", node.getmempoolancestors)
        assert_raises_rpc_error(-1, "getmempoolancestors txid (verbose)", node.getmempoolancestors, "00" * 32, True, 1)
        assert_raises_rpc_error(-1, "getmempoolinfo", node.getmempoolinfo, 1)


if __name__ == '__main__':
    MempoolPackagesTest().main()
