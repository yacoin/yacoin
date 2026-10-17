#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test node disconnect and ban behavior

setban/listbanned/clearbanned: errors, subnets, expiry with mocktime,
persistence across a restart, the ban time (-bantime, relative, absolute),
reason and creation time of each entry, netmask and IPv6 entries;
disconnectnode by address and by id.
"""
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    peers,
    wait_until,
)

class DisconnectBanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.supports_cli = False

    def run_test(self):
        self.log.info("Connect nodes both way")
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)

        self.log.info("Test setban and listbanned RPCs")

        self.log.info("setban: successfully ban single IP address")
        assert_equal(len(peers(self.nodes[1])), 2)  # node1 should have 2 connections to node0 at this point
        self.nodes[1].setban(subnet="127.0.0.1", command="add")
        wait_until(lambda: len(peers(self.nodes[1])) == 0, timeout=10)
        assert_equal(len(peers(self.nodes[1])), 0)  # all nodes must be disconnected at this point
        assert_equal(len(self.nodes[1].listbanned()), 1)

        self.log.info("clearbanned: successfully clear ban list")
        self.nodes[1].clearbanned()
        assert_equal(len(self.nodes[1].listbanned()), 0)
        self.nodes[1].setban("127.0.0.0/24", "add")

        self.log.info("setban: fail to ban an already banned subnet")
        assert_equal(len(self.nodes[1].listbanned()), 1)
        assert_raises_rpc_error(-23, "IP/Subnet already banned", self.nodes[1].setban, "127.0.0.1", "add")

        self.log.info("setban: fail to ban an invalid subnet")
        assert_raises_rpc_error(-30, "Error: Invalid IP/Subnet", self.nodes[1].setban, "127.0.0.1/42", "add")
        assert_equal(len(self.nodes[1].listbanned()), 1)  # still only one banned ip because 127.0.0.1 is within the range of 127.0.0.0/24

        self.log.info("setban remove: fail to unban a non-banned subnet")
        assert_raises_rpc_error(-30, "Error: Unban failed", self.nodes[1].setban, "127.0.0.1", "remove")
        assert_equal(len(self.nodes[1].listbanned()), 1)

        self.log.info("setban remove: successfully unban subnet")
        self.nodes[1].setban("127.0.0.0/24", "remove")
        assert_equal(len(self.nodes[1].listbanned()), 0)
        self.nodes[1].clearbanned()
        assert_equal(len(self.nodes[1].listbanned()), 0)

        self.log.info("setban: test persistence across node restart")
        self.nodes[1].setban("127.0.0.0/32", "add")
        self.nodes[1].setban("127.0.0.0/24", "add")
        # Set the mocktime so we can control when bans expire
        old_time = int(time.time())
        self.set_mocktime(old_time)
        self.nodes[1].setban("192.168.0.1", "add", 1)  # ban for 1 seconds
        self.nodes[1].setban("2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/19", "add", 1000)  # ban for 1000 seconds
        listBeforeShutdown = self.nodes[1].listbanned()
        assert_equal("192.168.0.1/32", listBeforeShutdown[2]['address'])
        # Move time forward by 3 seconds so the third ban has expired
        self.set_mocktime(old_time + 3)
        assert_equal(len(self.nodes[1].listbanned()), 3)

        self.stop_node(1)
        self.start_node(1)

        listAfterShutdown = self.nodes[1].listbanned()
        assert_equal("127.0.0.0/24", listAfterShutdown[0]['address'])
        assert_equal("127.0.0.0/32", listAfterShutdown[1]['address'])
        assert_equal("/19" in listAfterShutdown[2]['address'], True)

        # Clear ban lists
        self.nodes[1].clearbanned()

        self.test_ban_details()
        self.log.info("Connect nodes both way")
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)

        self.log.info("Test disconnectnode RPCs")

        self.log.info("disconnectnode: fail to disconnect when calling with address and nodeid")
        address1 = self.nodes[0].getpeerinfo()[0]['addr']
        node1 = self.nodes[0].getpeerinfo()[0]['addr']
        assert_raises_rpc_error(-32602, "Only one of address and nodeid should be provided.", self.nodes[0].disconnectnode, address=address1, nodeid=node1)

        self.log.info("disconnectnode: fail to disconnect when calling with junk address")
        assert_raises_rpc_error(-29, "Node not found in connected nodes", self.nodes[0].disconnectnode, address="221B Baker Street")

        self.log.info("disconnectnode: successfully disconnect node by address")
        address1 = self.nodes[0].getpeerinfo()[0]['addr']
        self.nodes[0].disconnectnode(address=address1)
        wait_until(lambda: len(peers(self.nodes[0])) == 1, timeout=10)
        assert not [node for node in self.nodes[0].getpeerinfo() if node.get("addr") == address1]

        self.log.info("disconnectnode: successfully reconnect node")
        connect_nodes(self.nodes[0], 1)  # reconnect the node
        assert_equal(len(peers(self.nodes[0])), 2)
        assert [node for node in self.nodes[0].getpeerinfo() if node.get("addr") == address1]

        self.log.info("disconnectnode: successfully disconnect node by node id")
        id1 = self.nodes[0].getpeerinfo()[0]['id']
        self.nodes[0].disconnectnode(nodeid=id1)
        wait_until(lambda: len(peers(self.nodes[0])) == 1, timeout=10)
        assert not [node for node in self.nodes[0].getpeerinfo() if node.get("id") == id1]

    def test_ban_details(self):
        node = self.nodes[1]
        self.log.info("setban: ban times, reasons and listed addresses")
        self.restart_node(1, ["-bantime=1000"])
        t0 = self.mocktime
        node.setban("192.0.2.1", "add")  # -bantime
        node.setban("192.0.2.2", "add", -5)  # 0 or less: -bantime too
        node.setban("192.0.2.3", "add", 30)
        node.setban("192.0.2.4", "add", t0 + 5000, True)
        node.setban(subnet="192.0.2.5", command="add", bantime=t0 + 6000, absolute=True)
        node.setban("198.51.100.0/255.255.0.255", "add")  # a netmask that isn't a prefix
        node.setban("2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63", "add")
        expected = {
            "192.0.2.1/32": 1000,
            "192.0.2.2/32": 1000,
            "192.0.2.3/32": 30,
            "192.0.2.4/32": 5000,
            "192.0.2.5/32": 6000,
            "198.51.0.0/255.255.0.255": 1000,  # listed as the masked network
            "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128": 1000,
        }

        def ban_times():
            entries = node.listbanned()
            for entry in entries:
                assert_equal((entry['ban_created'], entry['ban_reason']), (t0, "manually added"))
            return {entry['address']: entry['banned_until'] - t0 for entry in entries}
        assert_equal(ban_times(), expected)

        self.log.info("setban: errors")
        assert_raises_rpc_error(-23, "Error: IP/Subnet already banned", node.setban, "192.0.2.1", "add", 99999)
        node.setban("203.0.113.0/24", "add")
        assert_raises_rpc_error(-23, "Error: IP/Subnet already banned", node.setban, "203.0.113.9", "add")
        assert_raises_rpc_error(-30, "Error: Unban failed. Requested address/subnet was not previously banned.",
                                node.setban, "203.0.113.9", "remove")
        node.setban("203.0.113.0/24", "remove")
        help_text = 'setban "subnet" "add|remove" (bantime) (absolute)'
        assert_raises_rpc_error(-1, help_text, node.setban, "192.0.2.9", "delete")
        assert_raises_rpc_error(-1, help_text, node.setban, "192.0.2.9")
        assert_raises_rpc_error(-30, "Error: Invalid IP/Subnet", node.setban, "localhost", "add")  # no DNS lookup
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node.setban, "192.0.2.9", "add", "100")
        assert_raises_rpc_error(-1, "List all banned IPs/Subnets.", node.listbanned, 1)
        assert_raises_rpc_error(-1, "Clear all banned IPs.", node.clearbanned, 1)
        assert_equal(ban_times(), expected)

        self.log.info("setban: a ban is listed until its last second")
        self.set_mocktime(t0 + 30)
        assert_equal(ban_times(), expected)
        self.set_mocktime(t0 + 31)
        del expected["192.0.2.3/32"]
        assert_equal(ban_times(), expected)
        self.restart_node(1, ["-bantime=1000"])
        assert_equal(ban_times(), expected)

        self.log.info("setban: an absolute time in the past disconnects without a lasting ban")
        connect_nodes(self.nodes[0], 1)
        node.setban("127.0.0.1", "add", t0, True)
        wait_until(lambda: len(peers(node)) == 0, timeout=10)
        assert_equal(ban_times(), expected)
        node.clearbanned()
        self.restart_node(1, ["-bantime=1000"])
        assert_equal(node.listbanned(), [])


if __name__ == '__main__':
    DisconnectBanTest().main()
