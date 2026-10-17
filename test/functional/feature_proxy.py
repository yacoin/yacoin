#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the node's use of SOCKS5 proxies.

Port of Bitcoin Core 0.15's proxy_test.py.

- Start three SOCKS5 servers, the stub in test_framework/socks5.py:
    - conf1: unauthenticated only, IPv4
    - conf2: unauthenticated and authenticated, IPv4
    - conf3: unauthenticated and authenticated, IPv6 (if available)
- Nodes:
    - node0: -proxy=conf1 -proxyrandomize=1
    - node1: -proxy=conf1 -onion=conf2 -proxyrandomize=0
    - node2: -proxy=conf2 -proxyrandomize=1
    - node3: -proxy=conf3 -proxyrandomize=0 -noonion (if IPv6 is available)
- addnode onetry to an IPv4, an IPv6, an onion and a DNS name address and
  check what each proxy is asked: every target goes out as a domain name,
  with the port, and with credentials only where they are randomized and
  the server accepts them.
- getnetworkinfo's networks: the proxy and its credential setting per
  network.
- Invalid -proxy and -onion values stop the start-up.

The servers listen on ports the kernel picks, so parallel runs don't
collide. node3 runs with -dns=0: without a global IPv6 address the name
lookup of [::1] fails (getaddrinfo's AI_ADDRCONFIG), while a numeric
lookup works, and names still go to the proxy. -listenonion=0 keeps a
local Tor control port from changing the onion proxy.
"""

import socket

from test_framework.netutil import test_ipv6_local
from test_framework.socks5 import AddressType, Command, Socks5Command, Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True

    def start_server(self, addr, af, auth):
        conf = Socks5Configuration()
        conf.af = af
        conf.addr = (addr, 0)
        conf.unauth = True
        conf.auth = auth
        server = Socks5Server(conf)
        # The kernel picked the port; tell the nodes.
        conf.addr = server.s.getsockname()[:2]
        server.start()
        return conf, server

    def setup_nodes(self):
        self.have_ipv6 = test_ipv6_local()
        self.conf1, self.serv1 = self.start_server('127.0.0.1', socket.AF_INET, False)
        self.conf2, self.serv2 = self.start_server('127.0.0.1', socket.AF_INET, True)
        if self.have_ipv6:
            self.conf3, self.serv3 = self.start_server('::1', socket.AF_INET6, True)
        else:
            self.log.warning("Testing without local IPv6 support")

        args = [
            ['-listen', '-proxy=%s:%i' % self.conf1.addr, '-proxyrandomize=1'],
            ['-listen', '-proxy=%s:%i' % self.conf1.addr, '-onion=%s:%i' % self.conf2.addr, '-proxyrandomize=0'],
            ['-listen', '-proxy=%s:%i' % self.conf2.addr, '-proxyrandomize=1'],
            []
        ]
        if self.have_ipv6:
            args[3] = ['-listen', '-proxy=[%s]:%i' % self.conf3.addr[:2], '-proxyrandomize=0', '-noonion', '-dns=0']
        args = [a + ['-listenonion=0'] for a in args]
        self.add_nodes(self.num_nodes, extra_args=args)
        self.start_nodes()

    def node_test(self, node, proxies, auth, test_onion=True):
        rv = []
        # Test: outgoing IPv4 connection through node
        node.addnode("15.61.23.23:1234", "onetry")
        cmd = proxies[0].queue.get()
        assert isinstance(cmd, Socks5Command)
        # Note: bitcoind's SOCKS5 implementation only sends atyp DOMAINNAME, even if connecting directly to IPv4/IPv6
        assert_equal(cmd.atyp, AddressType.DOMAINNAME)
        assert_equal(cmd.addr, b"15.61.23.23")
        assert_equal(cmd.port, 1234)
        if not auth:
            assert_equal(cmd.username, None)
            assert_equal(cmd.password, None)
        rv.append(cmd)

        if self.have_ipv6:
            # Test: outgoing IPv6 connection through node
            node.addnode("[1233:3432:2434:2343:3234:2345:6546:4534]:5443", "onetry")
            cmd = proxies[1].queue.get()
            assert isinstance(cmd, Socks5Command)
            assert_equal(cmd.atyp, AddressType.DOMAINNAME)
            assert_equal(cmd.addr, b"1233:3432:2434:2343:3234:2345:6546:4534")
            assert_equal(cmd.port, 5443)
            if not auth:
                assert_equal(cmd.username, None)
                assert_equal(cmd.password, None)
            rv.append(cmd)

        if test_onion:
            # Test: outgoing onion connection through node
            node.addnode("bitcoinostk4e4re.onion:8333", "onetry")
            cmd = proxies[2].queue.get()
            assert isinstance(cmd, Socks5Command)
            assert_equal(cmd.atyp, AddressType.DOMAINNAME)
            assert_equal(cmd.addr, b"bitcoinostk4e4re.onion")
            assert_equal(cmd.port, 8333)
            if not auth:
                assert_equal(cmd.username, None)
                assert_equal(cmd.password, None)
            rv.append(cmd)

        # Test: outgoing DNS name connection through node
        node.addnode("node.noumenon:8333", "onetry")
        cmd = proxies[3].queue.get()
        assert isinstance(cmd, Socks5Command)
        assert_equal(cmd.atyp, AddressType.DOMAINNAME)
        assert_equal(cmd.addr, b"node.noumenon")
        assert_equal(cmd.port, 8333)
        if not auth:
            assert_equal(cmd.username, None)
            assert_equal(cmd.password, None)
        rv.append(cmd)

        for cmd in rv:
            assert_equal(cmd.cmd, Command.CONNECT)
        return rv

    def run_test(self):
        self.log.info("node0: randomized credentials, but the server takes no authentication")
        # The server picks "no authentication", so no credentials are sent.
        self.node_test(self.nodes[0], [self.serv1, self.serv1, self.serv1, self.serv1], False)
        self.log.info("node1: separate onion proxy, no randomization")
        self.node_test(self.nodes[1], [self.serv1, self.serv1, self.serv2, self.serv1], False)
        self.log.info("node2: randomized credentials with an authenticating server")
        rv = self.node_test(self.nodes[2], [self.serv2, self.serv2, self.serv2, self.serv2], True)
        # Each connection uses unique credentials
        credentials = set((x.username, x.password) for x in rv)
        assert_equal(len(credentials), len(rv))
        for username, password in credentials:
            assert username is not None and password is not None

        if self.have_ipv6:
            self.log.info("node3: IPv6 proxy, onion disabled")
            self.node_test(self.nodes[3], [self.serv3, self.serv3, self.serv3, self.serv3], False, False)

        self.log.info("getnetworkinfo shows the proxy per network")

        def networks_dict(d):
            r = {}
            for x in d['networks']:
                r[x['name']] = x
            return r

        def network(name, proxy, randomize, limited=False):
            return {'name': name, 'limited': limited, 'reachable': not limited,
                    'proxy': proxy, 'proxy_randomize_credentials': randomize}

        p1 = '%s:%i' % self.conf1.addr
        p2 = '%s:%i' % self.conf2.addr
        n0 = networks_dict(self.nodes[0].getnetworkinfo())
        for net in ['ipv4', 'ipv6', 'onion']:
            assert_equal(n0[net], network(net, p1, True))

        n1 = networks_dict(self.nodes[1].getnetworkinfo())
        for net in ['ipv4', 'ipv6']:
            assert_equal(n1[net], network(net, p1, False))
        assert_equal(n1['onion'], network('onion', p2, False))

        n2 = networks_dict(self.nodes[2].getnetworkinfo())
        for net in ['ipv4', 'ipv6', 'onion']:
            assert_equal(n2[net], network(net, p2, True))

        if self.have_ipv6:
            p3 = '[%s]:%i' % self.conf3.addr[:2]
            n3 = networks_dict(self.nodes[3].getnetworkinfo())
            for net in ['ipv4', 'ipv6']:
                assert_equal(n3[net], network(net, p3, False))
            # -noonion only limits the network; the proxy stays set.
            assert_equal(n3['onion'], network('onion', p3, False, limited=True))

        self.log.info("Invalid -proxy and -onion values are init errors")
        self.stop_node(0)
        # -dns=0: the bad names are never sent to a resolver.
        for arg, opt in [("-proxy=1.2.3.4:x", "-proxy"), ("-onion=1.2.3.4:x", "-onion")]:
            self.nodes[0].assert_start_raises_init_error(
                ["-dns=0", arg],
                "Error: Invalid %s address or hostname: '1.2.3.4:x'" % opt)
        # A valid lookup that gives an unusable address
        for arg, opt in [("-proxy=0.0.0.0:9050", "-proxy"), ("-onion=0.0.0.0:9050", "-onion")]:
            self.nodes[0].assert_start_raises_init_error(
                [arg],
                "Error: Invalid %s address or hostname: '0.0.0.0:9050'" % opt)


if __name__ == '__main__':
    ProxyTest().main()
