#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the YACoin parts of the test framework.

Later tests rely on these helpers, so check them against a real node:
- node exit codes and the signal helpers (TestNode.wait_until_stopped,
  send_signal, wait_for_exit).
- connect_nodes returns only when both sides finished the handshake, and
  peers() drops YACoin's extra getpeerinfo element.
"""

import signal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    p2p_port,
    peers,
)


class FrameworkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # The connection checks connect the nodes themselves.
        self.setup_nodes()

    def run_test(self):
        self.test_exit_codes()
        self.test_connect_nodes()

    def test_exit_codes(self):
        node = self.nodes[1]

        self.log.info("SIGTERM shuts the node down cleanly (exit code 0)")
        node.send_signal(signal.SIGTERM)
        assert_equal(node.wait_for_exit(), 0)
        assert_equal(node.read_stderr(), "")
        assert not node.running
        self.start_node(1)

        self.log.info("wait_until_stopped accepts the expected exit code")
        node.send_signal(signal.SIGKILL)
        node.wait_until_stopped(expected_ret_code=-signal.SIGKILL)
        self.start_node(1)

        self.log.info("wait_until_stopped fails on an unexpected exit code, and the node can be restarted")
        node.send_signal(signal.SIGKILL)
        try:
            node.wait_until_stopped()
        except AssertionError as e:
            assert "Node returned exit code -9 (SIGKILL), expected 0" in str(e), str(e)
        else:
            raise AssertionError("wait_until_stopped did not fail on exit code -9")
        assert not node.running
        self.start_node(1)
        assert_equal(node.getblockcount(), 0)

    def test_connect_nodes(self):
        self.log.info("peers() drops the extra getpeerinfo element")
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)
        assert_equal(peers(self.nodes[0]), [])

        self.log.info("connect_nodes returns when both sides finished the handshake")
        connect_nodes(self.nodes[0], 1)
        # No waiting here: both sides must already agree.
        outbound = peers(self.nodes[0])
        inbound = peers(self.nodes[1])
        assert_equal(len(outbound), 1)
        assert_equal(len(inbound), 1)
        assert_equal(outbound[0]['addr'], "127.0.0.1:%d" % p2p_port(1))
        assert not outbound[0]['inbound']
        assert inbound[0]['inbound']
        assert outbound[0]['version'] != 0 and inbound[0]['version'] != 0
        assert 'verack' in inbound[0]['bytesrecv_per_msg']
        assert 'pong' in outbound[0]['bytesrecv_per_msg']


if __name__ == '__main__':
    FrameworkTest().main()
