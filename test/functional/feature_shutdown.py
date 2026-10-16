#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the stop RPC.

- stop while another connection waits in waitfornewblock: the waiting call
  returns the current tip and the node exits with code 0;
- stop accepts one (ignored) argument and rejects two.
"""

from threading import Thread

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    wait_until,
)


class ShutdownTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getbestblockhash()

        self.log.info("stop during waitfornewblock")
        rpc = get_rpc_proxy(node.url, 1, timeout=600, coveragedir=node.coverage_dir)
        rpc.getblockcount()  # open the connection
        result = {}
        waiter = Thread(target=lambda: result.update(block=rpc.waitfornewblock()))
        waiter.start()
        wait_until(lambda: len(node.getrpcinfo()['active_commands']) == 2)
        assert_equal(node.stop(), "Yacoin server stopping")
        node.wait_until_stopped()
        waiter.join(10)
        assert not waiter.is_alive()
        assert_equal(result['block'], {'hash': genesis, 'height': 0})

        self.log.info("stop with one argument")
        self.start_node(0)
        assert_equal(node.stop(1), "Yacoin server stopping")
        node.wait_until_stopped()

        self.log.info("stop with two arguments")
        self.start_node(0)
        assert_raises_rpc_error(-1, "stop\n\nStop Yacoin server.", node.stop, 1, 2)


if __name__ == '__main__':
    ShutdownTest().main()
