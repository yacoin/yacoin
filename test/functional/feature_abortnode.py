#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a node whose undo data is missing.

node0's rev*.dat files are deleted while it runs, so it can't disconnect its
tip:
- invalidateblock of the tip returns null and the tip stays (as in Bitcoin
  Core);
- a reorg to a longer chain from node1 should make node0 shut down with a
  fatal error, as Bitcoin Core 0.19+ does; today it stays on its tip (known
  bug VdCO5Ac4).
After a restart (refused: corrupted block database), -reindex recovers it.
"""

import glob
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    wait_until,
)


class AbortNodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.block_fork_1_0 = 1

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def undo_failures(self):
        with open(os.path.join(self.nodes[0].datadir, 'debug.log'), encoding='utf-8') as f:
            return f.read().count("DisconnectBlock(): failure reading undo data")

    def run_test(self):
        node0, node1 = self.nodes
        self.mine_with_mocktime(node0, 5)
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        self.mine_with_mocktime(node0, 3, sync=False)
        tip = node0.getbestblockhash()
        for path in glob.glob(os.path.join(node0.datadir, 'blocks', 'rev*.dat')):
            os.remove(path)

        self.log.info("invalidateblock without undo data")
        assert_equal(node0.invalidateblock(tip), None)
        assert_equal(node0.getbestblockhash(), tip)
        assert_equal(self.undo_failures(), 1)

        self.log.info("Reorg without undo data")
        self.mine_with_mocktime(node1, 5, sync=False)
        connect_nodes(node0, 1)
        wait_until(lambda: self.undo_failures() >= 2)
        self.known_failure("R-16 (VdCO5Ac4)", lambda: node0.wait_until_stopped(timeout=5), "not true after")
        assert_equal(node0.getbestblockhash(), tip)

        self.log.info("Restart and -reindex")
        self.stop_node(0)
        node0.assert_start_raises_init_error([], "Corrupted block database detected", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, ["-reindex"])
        connect_nodes(node0, 1)
        self.sync_blocks()


if __name__ == '__main__':
    AbortNodeTest().main()
