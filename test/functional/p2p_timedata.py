#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the time offset the node takes from its peers' version messages.

Each peer's offset is its version time minus the node's clock. The node
keeps one sample per peer IP, starting with its own 0, and uses the median
once there are at least 5 samples and an odd number of them, as long as it
is within -maxtimeadjustment; otherwise the offset is 0, and if no peer
is within 5 minutes of the node's clock a warning is set (once per
process).

The peers connect from distinct 127.0.0.N addresses (Linux only). A fixed
mocktime makes every offset exact. The offsets only affect this node's
clock checks, so nothing else is done on these nodes.
"""

import sys
import time

from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, peers

WARNING = ("Please check that your computer's date and time are correct! "
           "If your clock is wrong, yacoind will not work properly.")


class TimePeer(P2PInterface):
    """Sends a version message with the given time."""
    def __init__(self, ntime):
        super().__init__()
        self.ntime = ntime

    def peer_connect(self, *args, **kwargs):
        create_conn = super().peer_connect(*args, **kwargs)
        self.on_connection_send_msg.nTime = self.ntime
        return create_conn


class TimeDataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [["-maxtimeadjustment=600"], [], []]

    def setup_network(self):
        self.setup_nodes()

    def connect(self, node, ip, offset):
        node.add_p2p_connection(TimePeer(self.mocktime + offset), local_addr=(ip, 0))
        peer = peers(node)[-1]
        assert peer['addr'].startswith(ip + ":"), peer['addr']
        assert_equal(peer['timeoffset'], offset)

    def timeoffset(self, node):
        return node.getnetworkinfo()['timeoffset']

    def run_test(self):
        if not sys.platform.startswith('linux'):
            raise SkipTest("needs the whole of 127.0.0.0/8 on the loopback interface (Linux)")
        self.set_mocktime(int(time.time()))
        self.test_median()
        self.test_warning()
        self.test_no_warning()

    def test_median(self):
        node = self.nodes[0]
        self.log.info("The median applies from 5 samples")
        for i, offset in enumerate([100, 100, 200]):
            self.connect(node, "127.0.0.%d" % (i + 2), offset)
            assert_equal(self.timeoffset(node), 0)
        self.connect(node, "127.0.0.5", 300)
        # samples 0, 100, 100, 200, 300
        assert_equal(self.timeoffset(node), 100)

        self.log.info("An even number of samples doesn't change the offset")
        self.connect(node, "127.0.0.6", 5000)
        assert_equal(self.timeoffset(node), 100)
        self.connect(node, "127.0.0.7", 5000)
        # samples 0, 100, 100, 200, 300, 5000, 5000
        assert_equal(self.timeoffset(node), 200)

        self.log.info("A second peer from a known IP adds no sample")
        with node.assert_debug_log([], unexpected_msgs=["added time data"]):
            self.connect(node, "127.0.0.2", -3000)
        assert_equal(self.timeoffset(node), 200)

        self.log.info("Negative offsets")
        self.connect(node, "127.0.0.8", -700)
        self.connect(node, "127.0.0.9", -700)
        # samples -700, -700, 0, 100, 100, 200, 300, 5000, 5000
        assert_equal(self.timeoffset(node), 100)
        assert_equal(node.getnetworkinfo()['warnings'], "")

    def test_warning(self):
        node = self.nodes[1]
        self.log.info("A median beyond -maxtimeadjustment (4200 s) gives 0 and a warning")
        for i in range(4):
            self.connect(node, "127.0.1.%d" % (i + 2), 5000)
        assert_equal(self.timeoffset(node), 0)
        assert_equal(node.getnetworkinfo()['warnings'], WARNING)
        node.disconnect_p2ps()
        # The node also prints the warning.
        self.stop_node(1, expected_stderr="Warning: " + WARNING)

    def test_no_warning(self):
        node = self.nodes[2]
        self.log.info("No warning when a peer is within 5 minutes")
        for i, offset in enumerate([5000, 5000, 5000, 299]):
            self.connect(node, "127.0.2.%d" % (i + 2), offset)
        assert_equal(self.timeoffset(node), 0)
        assert_equal(node.getnetworkinfo()['warnings'], "")
        self.log.info("Within -maxtimeadjustment again")
        for i in range(2):
            self.connect(node, "127.0.2.%d" % (i + 10), -4200)
        # samples -4200, -4200, 0, 299, 5000, 5000, 5000
        assert_equal(self.timeoffset(node), 299)


if __name__ == '__main__':
    TimeDataTest().main()
