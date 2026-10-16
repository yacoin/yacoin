#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test restarting the node with -reindex and -reindex-fast.

Builds a chain with wallet payments, a token, a losing 2-block fork and
address-index entries, records the state of node0 (per-height hash and mint,
money supply, block value, next subsidy, balance, chain tips, tracked
outputs, address index, tokens), and checks that it is unchanged after:

- a plain restart, -reindex and -reindex-fast; a block mined afterwards pays
  the recorded subsidy;
- -reindex over a block file whose records are out of order;
- -reindex-fast over a block file in which two records of equal size were
  swapped (known bug H0aGvZOs: the chain ends before the second one);
- -reindex-fast after kill -9 right after mining, and with blocks/index
  deleted, checking every block's hash.
"""

import os
import shutil
import signal

from test_framework.messages import COIN
from test_framework.mininode import MAGIC_BYTES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    read_block_file,
)

BASE = ["-addressindex=1", "-tokenindex=1", "-tokenSupportBlockNumber=10"]
MAGIC = MAGIC_BYTES['mainnet']


def record_block(data, record):
    pos, size = record
    return data[pos + 8:pos + 8 + size]


def swap_records(path, a, b):
    """Swap records a < b of a block file."""
    data, records = read_block_file(path, MAGIC)
    (pa, sa), (pb, sb) = records[a], records[b]
    ra, rb = data[pa:pa + 8 + sa], data[pb:pb + 8 + sb]
    with open(path, 'wb') as f:
        f.write(data[:pa] + rb + data[pa + 8 + sa:pb] + ra + data[pb + 8 + sb:])


class ReindexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.block_fork_1_0 = 1
        self.extra_args = [BASE, BASE, []]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def blk_file(self):
        return os.path.join(self.nodes[0].datadir, 'blocks', 'blk00000.dat')

    def snapshot(self):
        node = self.nodes[0]
        blocks = []
        for h in range(node.getblockcount() + 1):
            block_hash = node.getblockhash(h)
            blocks.append((block_hash, node.getblock(block_hash)['mint']))
        return {
            'blocks': blocks,
            'moneysupply': node.getinfo()['moneysupply'],
            'blockvalue': node.getmininginfo()['blockvalue'],
            'subsidy': node.getsubsidy(),
            'balance': node.getbalance(),
            'tips': sorted((t['hash'], t['height'], t['branchlen'], t['status']) for t in node.getchaintips()),
            'txouts': [node.gettxout(txid, n, False) for txid, n in self.tracked],
            'balances': [node.getaddressbalance({'addresses': [a]}) for a in self.addresses],
            'utxos': [node.getaddressutxos({'addresses': [a]}) for a in self.addresses],
            'tokens': node.listtokens('*', True),
            'holders': node.listaddressesbytoken('REINDEXTOK'),
        }

    def check_blocks(self):
        """Every block of node0's chain can be read and hashes to its index entry."""
        node = self.nodes[0]
        for h in range(node.getblockcount() + 1):
            block_hash = node.getblockhash(h)
            assert_equal(node.getblock(block_hash)['hash'], block_hash)
            assert_equal(node.calculateblockhash(node.getblock(block_hash, False)), block_hash)

    def restart(self, args=()):
        self.stop_node(0)
        self.start_node(0, BASE + list(args))

    def run_test(self):
        node0, node1, node2 = self.nodes
        # node2 only provides receive-only addresses.
        self.addresses = [node2.getnewaddress() for _ in range(3)]
        self.stop_node(2)
        self.tracked = []

        self.log.info("Build the chain")
        self.mine_with_mocktime(node1, 12)
        self.mine_with_mocktime(node0, 8)
        for i in range(10):
            address = self.addresses[i % 3]
            txid = node1.sendtoaddress(address=address, amount=1 + i)
            vout = [o['n'] for o in node1.decoderawtransaction(node1.gettransaction(txid)['hex'])['vout']
                    if o['scriptPubKey'].get('addresses') == [address]]
            self.tracked.append((txid, vout[0]))
            self.mine_with_mocktime(node1, 4)
        node1.issue("REINDEXTOK", 1000, 0, True, False, "", node1.getnewaddress(), "")
        self.mine_with_mocktime(node1, 1)
        node1.transfer("REINDEXTOK", 100, self.addresses[0])
        self.mine_with_mocktime(node1, 1)
        # A losing fork of 2 node0 blocks, which stays in node0's block file.
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        self.mine_with_mocktime(node0, 2, sync=False)
        self.mine_with_mocktime(node1, 3, sync=False)
        connect_nodes(node0, 1)
        self.sync_blocks(self.nodes[:2])
        self.mine_with_mocktime(node1, 5)
        tips = node0.getchaintips()
        assert_equal(len(tips), 2)
        assert_equal(sorted(t['branchlen'] for t in tips), [0, 2])

        state = self.snapshot()
        assert_equal(node0.verifychain(4, 0), True)

        self.log.info("Plain restart")
        self.restart()
        assert_equal(self.snapshot(), state)

        self.log.info("-reindex")
        with node0.assert_debug_log(["Reindexing block file blk00000.dat...", "Reindexing finished"]):
            self.restart(["-reindex"])
        assert_equal(self.snapshot(), state)

        self.log.info("-reindex-fast")
        with node0.assert_debug_log(["Reindexing block index and chainstate in fast mode ...", "Reindexing finished"]):
            self.restart(["-reindex-fast"])
        assert_equal(self.snapshot(), state)

        self.log.info("A block mined after the reindex pays the recorded subsidy")
        block_hash = self.mine_with_mocktime(node0, 1, sync=False)[0]
        coinbase = node0.getblock(block_hash)['tx'][0]
        assert_equal(int(node0.gettxout(coinbase, 0)['value'] * COIN), state['subsidy'])
        connect_nodes(node0, 1)
        self.sync_blocks(self.nodes[:2])
        state = self.snapshot()

        self.log.info("-reindex over out-of-order block records")
        self.stop_node(0)
        swap_records(self.blk_file(), 14, 16)
        with node0.assert_debug_log(["Out of order block", "Processing out of order child"]):
            self.start_node(0, BASE + ["-reindex"])
        assert_equal(self.snapshot(), state)

        self.log.info("-reindex-fast over two swapped records of equal size")
        heights = range(1, 14)
        hexes = {h: node0.getblock(node0.getblockhash(h), False) for h in heights}
        self.stop_node(0)
        data, records = read_block_file(self.blk_file(), MAGIC)
        for h in heights:
            assert_equal(record_block(data, records[h]).hex(), hexes[h])
        pairs = [(a, b) for a in heights for b in heights if b > a + 1 and records[a][1] == records[b][1]]
        assert pairs, "no two equal-size block records among heights 1-13"
        a, b = pairs[0]
        swap_records(self.blk_file(), a, b)
        self.start_node(0, BASE + ["-reindex-fast"])
        tip_height = len(state['blocks']) - 1
        self.known_failure("R-B2 (H0aGvZOs)", lambda: assert_equal(node0.getblockcount(), tip_height),
                           "not(%d == %d)" % (b - 1, tip_height))
        self.restart(["-reindex"])
        assert_equal(self.snapshot(), state)

        self.log.info("-reindex-fast after kill -9 right after mining")
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        self.mine_with_mocktime(node0, 3, sync=False)
        tip = node0.getbestblockhash()
        node0.send_signal(signal.SIGKILL)
        assert_equal(node0.wait_for_exit(), -signal.SIGKILL)
        self.start_node(0, BASE + ["-reindex-fast"])
        assert_equal(node0.getbestblockhash(), tip)
        self.check_blocks()
        connect_nodes(node0, 1)
        self.sync_blocks(self.nodes[:2])
        state = self.snapshot()

        self.log.info("-reindex-fast with blocks/index deleted")
        self.stop_node(0)
        shutil.rmtree(os.path.join(node0.datadir, 'blocks', 'index'))
        self.start_node(0, BASE + ["-reindex-fast"])
        assert_equal(self.snapshot(), state)
        self.check_blocks()


if __name__ == '__main__':
    ReindexTest().main()
