#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -walletnotify, -blocknotify and -alertnotify options.

- -walletnotify runs for each wallet transaction when it arrives and
  when it confirms.
- -blocknotify runs for each new tip (known failure: not implemented).
- -alertnotify runs once when more than 50 of the last 100 blocks have
  an unknown version (built here as version 8 blocks); the warning shows
  in getinfo, getmininginfo and getnetworkinfo, without safe mode. After
  a restart it is gone until the next block is connected.
"""

import os

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
    assert_block_accepted,
    create_block_yac,
    get_template,
    solve_block,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_is_hash_string, wait_until

WARNING = "Warning: Unknown block versions being mined! It's possible unknown rules are in effect"
# The command gets the warning without the characters SanitizeString drops.
ALERT_LINE = "Warning: Unknown block versions being mined Its possible unknown rules are in effect"


def read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, encoding='utf8') as f:
        return f.read().splitlines()


class NotificationsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # solve_block hashes through batch requests.
        self.supports_cli = False

    def setup_network(self):
        self.block_file = os.path.join(self.options.tmpdir, 'blocks.txt')
        self.alert_file = os.path.join(self.options.tmpdir, 'alert.txt')
        self.wallet_file = os.path.join(self.options.tmpdir, 'wallet.txt')
        self.node0_args = ['-blocknotify=echo %%s >> %s' % self.block_file,
                           '-alertnotify=echo %%s >> %s' % self.alert_file]
        self.extra_args = [self.node0_args, ['-walletnotify=echo %%s >> %s' % self.wallet_file]]
        super().setup_network()

    def run_test(self):
        self.set_mocktime(TIME_GENESIS_BLOCK + 60)
        self.test_walletnotify()
        self.test_blocknotify()
        self.test_alertnotify()

    def test_walletnotify(self):
        node0, node1 = self.nodes
        self.log.info("-walletnotify: each transaction when it arrives and when it confirms")
        self.mine_with_mocktime(node0, 20)
        txids = [node0.sendtoaddress(address=node1.getnewaddress(), amount=1) for _ in range(3)]
        self.sync_mempools()
        self.mine_with_mocktime(node0, 1)
        wait_until(lambda: len(read_lines(self.wallet_file)) >= 6)
        lines = read_lines(self.wallet_file)
        assert_equal(set(lines), set(txids))
        assert_equal(set(lines), set(t['txid'] for t in node1.listtransactions('*', 100)))
        for txid in txids:
            assert lines.count(txid) >= 2, (txid, lines)

    def test_blocknotify(self):
        node0 = self.nodes[0]
        self.log.info("-blocknotify: each new tip")

        def check():
            # The block notifications would have been started before the
            # wallet ones waited for above; allow a little more time.
            wait_until(lambda: os.path.isfile(self.block_file), timeout=2)
            lines = read_lines(self.block_file)
            for block_hash in lines:
                assert_equal(node0.getblockheader(block_hash)['confirmations'] > 0, True)
            assert_equal(lines[-1], node0.getbestblockhash())
        self.known_failure("uxP8YzbJ item 1", check, expected="not true after 2 seconds")

    def mine_version_8(self, n):
        node0 = self.nodes[0]
        for _ in range(n):
            # Moving the clock 60 s per block keeps the block spacing.
            self.set_mocktime(self.mocktime + 60)
            block = create_block_yac(node0, tmpl=get_template(node0))
            block.nVersion = 8
            assert_block_accepted(node0, solve_block(node0, block))

    def test_alertnotify(self):
        node0, node1 = self.nodes
        self.log.info("-alertnotify: more than 50 of the last 100 blocks have an unknown version")
        # node1 is a peer, which getblocktemplate needs.
        self.mine_version_8(50)
        assert_equal(node0.getinfo()['errors'], '')
        assert_equal(read_lines(self.alert_file), [])

        with node0.assert_debug_log(["warning='51 of last 100 blocks have unexpected version'"]):
            self.mine_version_8(1)
        wait_until(lambda: read_lines(self.alert_file) == [ALERT_LINE])
        assert_equal(node0.getinfo()['errors'], WARNING)
        assert_equal(node0.getmininginfo()['errors'], WARNING)
        assert_equal(node0.getnetworkinfo()['warnings'], WARNING)
        # A status bar warning only: the node is not in safe mode.
        assert_is_hash_string(node0.sendtoaddress(address=node1.getnewaddress(), amount=1))

        self.log.info("The command runs only once per process")
        self.mine_version_8(4)
        self.sync_all()

        self.log.info("After a restart the warning is gone until the next block")
        self.restart_node(0, self.node0_args)
        assert_equal(node0.getinfo()['errors'], '')
        # Any late second notification of the first process is in by now.
        assert_equal(read_lines(self.alert_file), [ALERT_LINE])
        self.mine_with_mocktime(node0, 1, sync=False)
        assert_equal(node0.getinfo()['errors'], WARNING)
        wait_until(lambda: read_lines(self.alert_file) == [ALERT_LINE] * 2)


if __name__ == '__main__':
    NotificationsTest().main()
