#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test importing blocks from a file at startup.

node0 mines 30 blocks (with a token) and stops; its blk00000.dat is copied
to a file, which fresh nodes import:

- -loadblock=<file>: same tip and tokens; importing it again loads nothing;
  a missing file is only a warning;
- <datadir>/bootstrap.dat: imported and renamed to bootstrap.dat.old;
- -loadblock with -stopafterblockimport: the node imports and exits (exit
  code 1 today, VdCO5Ac4), and has the blocks after a restart.
"""

import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

BASE = ["-tokenindex=1", "-tokenSupportBlockNumber=10"]


class LoadblockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [BASE] * 4

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0, node1, node2, node3 = self.nodes
        self.mine_with_mocktime(node0, 12, sync=False)
        node0.issue("LOADTOK", 1000, 0, True, False, "", node0.getnewaddress(), "")
        self.mine_with_mocktime(node0, 18, sync=False)
        tip = node0.getbestblockhash()
        tokens = node0.listtokens('*', True)
        self.stop_node(0)
        blocks_file = os.path.join(self.options.tmpdir, 'blocks.dat')
        shutil.copyfile(os.path.join(node0.datadir, 'blocks', 'blk00000.dat'), blocks_file)

        self.log.info("-loadblock")
        with node1.assert_debug_log(["Importing blocks file %s..." % blocks_file,
                                     "Loaded 30 blocks from external file"]):
            self.restart_node(1, BASE + ["-loadblock=" + blocks_file])
        assert_equal(node1.getblockcount(), 30)
        assert_equal(node1.getbestblockhash(), tip)
        assert_equal(node1.listtokens('*', True), tokens)

        self.log.info("-loadblock of blocks the node already has")
        with node1.assert_debug_log(["Importing blocks file %s..." % blocks_file],
                                    unexpected_msgs=["blocks from external file"]):
            self.restart_node(1, BASE + ["-loadblock=" + blocks_file])
        assert_equal(node1.getbestblockhash(), tip)

        self.log.info("-loadblock of a missing file")
        missing = blocks_file + ".missing"
        with node1.assert_debug_log(["Warning: Could not open blocks file %s" % missing]):
            self.restart_node(1, BASE + ["-loadblock=" + missing])
        assert_equal(node1.getbestblockhash(), tip)

        self.log.info("bootstrap.dat")
        self.stop_node(2)
        bootstrap = os.path.join(node2.datadir, 'bootstrap.dat')
        shutil.copyfile(blocks_file, bootstrap)
        with node2.assert_debug_log(["Importing bootstrap.dat..."]):
            self.start_node(2)
        assert_equal(node2.getbestblockhash(), tip)
        assert not os.path.exists(bootstrap)
        assert os.path.exists(bootstrap + ".old")

        self.log.info("-stopafterblockimport")
        self.stop_node(3)
        with node3.assert_debug_log(["Stopping after block import", "Yacoin exited"]):
            node3.start(BASE + ["-loadblock=" + blocks_file, "-stopafterblockimport"])
            exit_code = node3.wait_for_exit(60)
        self.known_failure("R-18 (VdCO5Ac4)", lambda: assert_equal(exit_code, 0), "not(1 == 0)")
        self.start_node(3)
        assert_equal(node3.getbestblockhash(), tip)


if __name__ == '__main__':
    LoadblockTest().main()
