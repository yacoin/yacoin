#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that a second yacoind can't use a data directory in use.

node1 is started with node0's datadir while node0 runs: it exits with
the lock error, and node0 keeps working. (Core's wallet lock part is not
ported.)
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class FilelockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=None)
        self.nodes[0].start()
        self.nodes[0].wait_for_rpc_connection()

    def run_test(self):
        datadir = self.nodes[0].datadir
        self.log.info("Using datadir {}".format(datadir))

        self.log.info("Check that we can't start a second yacoind instance using the same datadir")
        expected_msg = "Error: Cannot obtain a lock on data directory {}. Yacoin Core is probably already running.".format(datadir)
        self.nodes[1].assert_start_raises_init_error(extra_args=['-datadir={}'.format(datadir), '-noserver'], expected_msg=expected_msg)
        assert_equal(self.nodes[0].getblockcount(), 0)


if __name__ == '__main__':
    FilelockTest().main()
