#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the parsing and effect of network options.

- Init errors for -onlynet, -externalip, -bind, -whitebind and -whitelist
  values, and for a -bind address that isn't on this machine.
- -bind and -whitebind: the listening sockets, and whitelisted peers on
  the -whitebind port only.
- -listen=0: no P2P listening socket.
- -onlynet: the other networks are limited; a manual onetry connection
  still goes out.
- -externalip: the local addresses and their scores, the score bump when
  a peer reports that address, and the address advertised to an outbound
  peer.
- -dns=0: a host name can't be connected to.

The nodes get -bind=127.0.0.1 explicitly (the framework's default bind is
off, for the -listen=0 case) and -listenonion=0, so a local Tor control
port can't change the network table.
"""

import socket
import sys
import time

from test_framework.mininode import P2PInterface
from test_framework.netutil import get_bind_addrs
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    connect_nodes,
    p2p_port,
    peers,
    rpc_port,
    wait_until,
)

BASE_ARGS = ["-bind=127.0.0.1", "-listenonion=0"]
LOCALHOST = "7f000001"


class AddrMePeer(P2PInterface):
    """Reports addr_me as the node's address in its version message."""
    def __init__(self, addr_me):
        super().__init__()
        self.addr_me = addr_me

    def peer_connect(self, *args, **kwargs):
        create_conn = super().peer_connect(*args, **kwargs)
        self.on_connection_send_msg.addrTo.ip = self.addr_me[0]
        self.on_connection_send_msg.addrTo.port = self.addr_me[1]
        return create_conn


def network(name, limited):
    return {'name': name, 'limited': limited, 'reachable': not limited,
            'proxy': '', 'proxy_randomize_credentials': False}


class NetArgsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.bind_to_localhost_only = False
        self.extra_args = [BASE_ARGS, BASE_ARGS + ["-connect=0"]]

    def setup_network(self):
        self.setup_nodes()

    def ipv4_binds(self, node):
        # Only IPv4: whether the RPC server's [::1] bind works depends on
        # the machine.
        return set(a for a in get_bind_addrs(node.process.pid) if len(a[0]) == 8)

    def run_test(self):
        self.set_mocktime(int(time.time()))
        self.p0 = p2p_port(0)
        self.test_init_errors()
        self.test_bind()
        self.test_onlynet()
        self.test_externalip()
        self.test_no_dns()

    def test_init_errors(self):
        node = self.nodes[0]
        self.stop_node(0)
        self.log.info("Init errors")
        # -dns=0: the bad value is never sent to a resolver.
        for args, msg in [
            (["-onlynet=foo"], "Error: Unknown network specified in -onlynet: 'foo'"),
            (["-dns=0", "-externalip=1.2.3.4:x"], "Error: Cannot resolve -externalip address: '1.2.3.4:x'"),
            (["-bind=1.2.3.4:x"], "Error: Cannot resolve -bind address: '1.2.3.4:x'"),
            (["-whitebind=127.0.0.1"], "Error: Need to specify a port with -whitebind: '127.0.0.1'"),
            (["-whitebind=127.0.0.1:x"], "Error: Cannot resolve -whitebind address: '127.0.0.1:x'"),
            (["-whitelist=1.2.3.4/99"], "Error: Invalid netmask specified in -whitelist: '1.2.3.4/99'"),
            (["-whitelist=foo"], "Error: Invalid netmask specified in -whitelist: 'foo'"),
        ]:
            node.assert_start_raises_init_error(BASE_ARGS + args, msg)
        # 192.0.2.1 (TEST-NET-1) is not an address of this machine.
        node.assert_start_raises_init_error(
            ["-bind=192.0.2.1", "-listenonion=0"],
            r"Error: Unable to bind to 192\.0\.2\.1:%d on this computer.*\nError: Failed to listen on any port\. Use -listen=0 if you want this\." % self.p0,
            match=ErrorMatch.FULL_REGEX)

    def test_bind(self):
        node = self.nodes[0]
        p2 = p2p_port(2)
        self.log.info("-whitebind: a second listening port with whitelisted peers")
        self.start_node(0, BASE_ARGS + ["-whitebind=127.0.0.1:%d" % p2])
        if sys.platform.startswith('linux'):
            assert_equal(self.ipv4_binds(node), {(LOCALHOST, self.p0), (LOCALHOST, p2), (LOCALHOST, rpc_port(0))})
        node.add_p2p_connection(P2PInterface())
        node.add_p2p_connection(P2PInterface(), dstport=p2)
        assert_equal(sorted((p['addrbind'], p['whitelisted']) for p in peers(node)),
                     sorted([("127.0.0.1:%d" % self.p0, False), ("127.0.0.1:%d" % p2, True)]))
        node.disconnect_p2ps()

        self.log.info("-listen=0: no P2P listening socket")
        self.restart_node(0, ["-listen=0", "-listenonion=0"])
        if sys.platform.startswith('linux'):
            assert_equal(self.ipv4_binds(node), {(LOCALHOST, rpc_port(0))})
        try:
            socket.create_connection(("127.0.0.1", self.p0), timeout=10).close()
            raise AssertionError("connected to a node started with -listen=0")
        except ConnectionRefusedError:
            pass

    def test_onlynet(self):
        node = self.nodes[0]
        self.log.info("-onlynet=ipv6 limits IPv4 and onion")
        self.restart_node(0, BASE_ARGS + ["-onlynet=ipv6"])
        assert_equal(node.getnetworkinfo()['networks'],
                     [network('ipv4', True), network('ipv6', False), network('onion', True)])
        # A manual connection ignores -onlynet (as in Bitcoin Core).
        node.addnode("127.0.0.1:%d" % p2p_port(1), "onetry")
        assert_equal([(p['addr'], p['inbound']) for p in peers(node)], [("127.0.0.1:%d" % p2p_port(1), False)])

        self.log.info("-onlynet=onion without a proxy limits every network")
        self.restart_node(0, BASE_ARGS + ["-onlynet=onion"])
        assert_equal(node.getnetworkinfo()['networks'],
                     [network('ipv4', True), network('ipv6', True), network('onion', True)])

    def test_externalip(self):
        node = self.nodes[0]
        self.log.info("-externalip: local addresses with the manual score")
        self.restart_node(0, BASE_ARGS + ["-externalip=1.2.3.4", "-externalip=5.6.7.8:1234"])

        def local_addresses():
            return sorted(node.getnetworkinfo()['localaddresses'], key=lambda a: a['address'])

        assert_equal(local_addresses(), [
            {'address': '1.2.3.4', 'port': self.p0, 'score': 4},
            {'address': '5.6.7.8', 'port': 1234, 'score': 4},
        ])

        self.log.info("A peer reporting one of them raises its score")
        node.add_p2p_connection(AddrMePeer(("1.2.3.4", 9999)))
        assert_equal(peers(node)[-1]['addrlocal'], "1.2.3.4:9999")
        assert_equal([a['score'] for a in local_addresses()], [5, 4])
        node.add_p2p_connection(AddrMePeer(("9.9.9.9", 9999)))
        assert_equal(peers(node)[-1]['addrlocal'], "9.9.9.9:9999")
        assert_equal([a['score'] for a in local_addresses()], [5, 4])
        node.disconnect_p2ps()

        self.log.info("An outbound peer learns the advertised address")
        connect_nodes(node, 1)
        # The address is queued before the handshake ends, so the first
        # addr message to the peer carries it.
        wait_until(lambda: "1.2.3.4:%d" % self.p0 in [a.get('address') for a in self.nodes[1].getaddrmaninfo()], timeout=60)

    def test_no_dns(self):
        node = self.nodes[0]
        self.log.info("-dns=0: no connection to a host name")
        self.restart_node(0, BASE_ARGS + ["-dns=0"])
        # onetry connects (or fails) within the RPC call.
        node.addnode("localhost:%d" % p2p_port(1), "onetry")
        assert_equal(peers(node), [])
        node.addnode("127.0.0.1:%d" % p2p_port(1), "onetry")
        assert_equal(len(peers(node)), 1)


if __name__ == '__main__':
    NetArgsTest().main()
