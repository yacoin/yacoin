#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC calls related to net.

Tests correspond to code in rpc/net.cpp: getconnectioncount, getnettotals,
getnetworkinfo, setnetworkactive, addnode, getaddednodeinfo, getpeerinfo,
ping, disconnectnode and getaddrmaninfo, with the shapes of their results.

The nodes run with -discover=0 (no machine-dependent local addresses),
-listenonion=0 (no Tor control port changing the onion network) and
-connect=0 (the node doesn't dial the addresses fed to its addrman, which
would lower their chance).
"""

import re
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    connect_nodes,
    p2p_port,
    peers,
    wait_until,
)
from test_framework.mininode import P2PInterface
from test_framework.messages import (
    CAddress,
    msg_addr,
    NODE_NETWORK,
)

PEER_KEYS = {
    'id', 'addr', 'addrbind', 'services', 'relaytxes', 'lastsend', 'lastrecv',
    'bytessent', 'bytesrecv', 'conntime', 'timeoffset', 'version', 'subver',
    'inbound', 'addnode', 'startingheight', 'banscore', 'synced_headers',
    'synced_blocks', 'inflight', 'whitelisted', 'bytessent_per_msg',
    'bytesrecv_per_msg',
}
# Present only after a pong (pingtime, minping), while a ping is pending
# (pingwait), or when the peer reported our address (addrlocal).
OPTIONAL_PEER_KEYS = {'pingtime', 'minping', 'pingwait', 'addrlocal'}
DATE_TIME = r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$'


class NetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-discover=0", "-listenonion=0", "-connect=0"]] * self.num_nodes
        self.supports_cli = False

    def run_test(self):
        # A fixed clock: the version time offsets are exactly 0, and the
        # addrman times are exact.
        self.set_mocktime(int(time.time()))
        self.log.info('An empty addrman')
        # Card iQg6oeoK item 2: getaddrmaninfo (like getpeerinfo) ends with a
        # {"size: ": n} element.
        assert_equal(self.nodes[0].getaddrmaninfo(), [{"size: ": 0}])

        self.log.info('Connect nodes both way')
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)

        self._test_connection_count()
        self._test_getnettotals()
        self._test_getnetworkinfo()
        self._test_getaddednodeinfo()
        self._test_getpeerinfo()
        self._test_getpeerinfo_shape()
        self._test_ping()
        self._test_disconnectnode()
        self._test_getaddrmaninfo()

    def _test_connection_count(self):
        # connect_nodes connects each node to the other
        assert_equal(self.nodes[0].getconnectioncount(), 2)

    def _test_getnettotals(self):
        # getnettotals totalbytesrecv and totalbytessent should be
        # consistent with getpeerinfo. Since the RPC calls are not atomic,
        # and messages might have been recvd or sent between RPC calls, call
        # getnettotals before and after and verify that the returned values
        # from getpeerinfo are bounded by those values.
        net_totals_before = self.nodes[0].getnettotals()
        peer_info = peers(self.nodes[0])
        net_totals_after = self.nodes[0].getnettotals()
        assert_equal(len(peer_info), 2)
        peers_recv = sum([peer['bytesrecv'] for peer in peer_info])
        peers_sent = sum([peer['bytessent'] for peer in peer_info])

        assert_greater_than_or_equal(peers_recv, net_totals_before['totalbytesrecv'])
        assert_greater_than_or_equal(net_totals_after['totalbytesrecv'], peers_recv)
        assert_greater_than_or_equal(peers_sent, net_totals_before['totalbytessent'])
        assert_greater_than_or_equal(net_totals_after['totalbytessent'], peers_sent)

        # Without -maxuploadtarget there is no upload target.
        assert_equal(net_totals_after['uploadtarget'], {
            'timeframe': 86400,
            'target': 0,
            'target_reached': False,
            'serve_historical_blocks': True,
            'bytes_left_in_cycle': 0,
            'time_left_in_cycle': 0,
        })

        # test getnettotals and getpeerinfo by doing a ping
        # the bytes sent/received should change
        # note ping and pong are 32 bytes each
        self.nodes[0].ping()
        wait_until(lambda: (self.nodes[0].getnettotals()['totalbytessent'] >= net_totals_after['totalbytessent'] + 32 * 2), timeout=1)
        wait_until(lambda: (self.nodes[0].getnettotals()['totalbytesrecv'] >= net_totals_after['totalbytesrecv'] + 32 * 2), timeout=1)

        peer_info_after_ping = peers(self.nodes[0])
        for before, after in zip(peer_info, peer_info_after_ping):
            assert_greater_than_or_equal(after['bytesrecv_per_msg'].get('pong', 0), before['bytesrecv_per_msg'].get('pong', 0) + 32)
            assert_greater_than_or_equal(after['bytessent_per_msg'].get('ping', 0), before['bytessent_per_msg'].get('ping', 0) + 32)

    def _test_getnetworkinfo(self):
        node = self.nodes[0]
        info = node.getnetworkinfo()
        # Card iQg6oeoK item 2: the help also lists fee fields that the
        # result doesn't have.
        assert_equal(sorted(info), sorted([
            'version', 'subversion', 'protocolversion', 'localservices',
            'localrelay', 'timeoffset', 'networkactive', 'connections',
            'networks', 'localaddresses', 'warnings',
        ]))
        assert isinstance(info['version'], int)
        assert re.match(r'^/Yacoin-WM:\d+\.\d+\.\d+(\.\d+)?\(testnode0\)/$', info['subversion']), info['subversion']
        assert_equal(info['protocolversion'], 70015)
        assert_equal(info['localservices'], "0000000000000001")
        assert_equal(info['localrelay'], True)
        assert_equal(info['timeoffset'], 0)
        assert_equal(info['localaddresses'], [])
        assert_equal(info['warnings'], "")
        # Onion is limited until a proxy for it is set.
        assert_equal(info['networks'], [
            {'name': 'ipv4', 'limited': False, 'reachable': True, 'proxy': '', 'proxy_randomize_credentials': False},
            {'name': 'ipv6', 'limited': False, 'reachable': True, 'proxy': '', 'proxy_randomize_credentials': False},
            {'name': 'onion', 'limited': True, 'reachable': False, 'proxy': '', 'proxy_randomize_credentials': False},
        ])
        assert_equal(info['networkactive'], True)
        assert_equal(info['connections'], 2)

        # setnetworkactive returns the new state.
        assert_equal(node.setnetworkactive(state=False), False)
        assert_equal(node.getnetworkinfo()['networkactive'], False)
        # Wait a bit for all sockets to close
        wait_until(lambda: node.getnetworkinfo()['connections'] == 0, timeout=3)

        assert_equal(node.setnetworkactive(state=True), True)
        assert_equal(node.setnetworkactive(state=True), True)
        self.log.info('Connect nodes both way')
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 0)

        assert_equal(node.getnetworkinfo()['networkactive'], True)
        assert_equal(node.getnetworkinfo()['connections'], 2)

    def _test_getaddednodeinfo(self):
        assert_equal(self.nodes[0].getaddednodeinfo(), [])
        # add a node (node2) to node0
        ip_port = "127.0.0.1:{}".format(p2p_port(2))
        self.nodes[0].addnode(node=ip_port, command='add')
        # check that the node has indeed been added
        added_nodes = self.nodes[0].getaddednodeinfo(ip_port)
        assert_equal(len(added_nodes), 1)
        assert_equal(added_nodes[0]['addednode'], ip_port)
        # check that a non-existent node returns an error
        assert_raises_rpc_error(-24, "Node has not been added", self.nodes[0].getaddednodeinfo, '1.1.1.1')
        # an unknown command gives the help text
        assert_raises_rpc_error(-1, 'addnode "node" "add|remove|onetry"', self.nodes[0].addnode, ip_port, 'foo')

    def _test_getpeerinfo(self):
        peer_info = [peers(x) for x in self.nodes]
        # check both sides of bidirectional connection between nodes
        # the address bound to on one side will be the source address for the other node
        assert_equal(peer_info[0][0]['addrbind'], peer_info[1][0]['addr'])
        assert_equal(peer_info[1][0]['addrbind'], peer_info[0][0]['addr'])

    def _test_getpeerinfo_shape(self):
        node = self.nodes[0]
        self.log.info('getpeerinfo fields of a node peer')
        wait_until(lambda: all('pingtime' in p for p in peers(node)))
        peer_info = node.getpeerinfo()
        # Card iQg6oeoK item 2: the list ends with a {"size: ": n} element.
        assert_equal(peer_info[-1], {"size: ": 2})
        assert_equal(len(peer_info), 3)
        for peer in peer_info[:-1]:
            keys = set(peer)
            assert PEER_KEYS <= keys, PEER_KEYS - keys
            assert keys <= PEER_KEYS | OPTIONAL_PEER_KEYS, keys - PEER_KEYS - OPTIONAL_PEER_KEYS
            assert_equal(peer['services'], "0000000000000001")
            assert_equal(peer['version'], 70015)
            assert '(testnode1)' in peer['subver'], peer['subver']
            assert_equal(peer['banscore'], 0)
            assert_equal(peer['inflight'], [])
            assert_equal(peer['whitelisted'], False)
            assert_equal(peer['addnode'], False)
            assert_equal(peer['timeoffset'], 0)
            assert_equal(peer['relaytxes'], True)
            # Card iQg6oeoK item 2: the times are date strings, while the
            # help says seconds since the epoch.
            for key in ['lastsend', 'lastrecv', 'conntime']:
                assert re.match(DATE_TIME, peer[key]), (key, peer[key])
        assert_equal(sorted(p['inbound'] for p in peer_info[:-1]), [False, True])

        self.log.info('getpeerinfo fields of a mininode peer')
        node.add_p2p_connection(P2PInterface())
        peer = peers(node)[-1]
        assert_equal(peer['services'], "0000000000000009")
        assert_equal(peer['version'], 70014)
        assert_equal(peer['subver'], "/python-mininode-tester:0.0.3/")
        assert_equal(peer['inbound'], True)
        # The mininode reports the address it connected to.
        assert_equal(peer['addrlocal'], "127.0.0.1:%d" % p2p_port(0))
        node.disconnect_p2ps()
        wait_until(lambda: len(peers(node)) == 2)

    def _test_ping(self):
        node = self.nodes[0]
        self.log.info('ping')
        # Every peer answers the RPC's ping with a 32-byte pong.
        before = [p['bytesrecv_per_msg'].get('pong', 0) for p in peers(node)]
        assert_equal(node.ping(), None)
        wait_until(lambda: all(a >= b + 32 for a, b in zip([p['bytesrecv_per_msg'].get('pong', 0) for p in peers(node)], before)))
        for peer in peers(node):
            assert_greater_than(peer['pingtime'], 0)

    def _test_disconnectnode(self):
        node = self.nodes[0]
        self.log.info('disconnectnode with an unknown id or an empty address')
        assert_raises_rpc_error(-29, "Node not found in connected nodes", node.disconnectnode, nodeid=999)
        assert_raises_rpc_error(-29, "Node not found in connected nodes", node.disconnectnode, "")

    def _test_getaddrmaninfo(self):
        node = self.nodes[0]
        self.log.info('getaddrmaninfo lists the addresses a peer sent')
        msg = msg_addr()
        for i in range(10):
            addr = CAddress()
            addr.time = self.mocktime - 100
            addr.nServices = NODE_NETWORK
            addr.ip = "123.%d.%d.1" % (100 + i, i + 1)
            addr.port = 8333 + i
            msg.addrs.append(addr)
        node.add_p2p_connection(P2PInterface()).send_and_ping(msg)
        # Stored with the 2 hour penalty for addresses learnt from a peer.
        stored = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self.mocktime - 100 - 2 * 60 * 60))
        expected = {}
        for a in msg.addrs:
            address = '%s:%d' % (a.ip, a.port)
            expected[address] = {'address': address, 'chance': 1, 'type': 'ipv4', 'time': stored}
        # addrman drops a new address whose slot is taken (rare: one /16
        # group per address); the size counts the entries it holds.
        size = node.getaddrmaninfo()[-1]["size: "]
        assert_greater_than_or_equal(size, 9)
        for network in [None, "ipv4"]:
            result = node.getaddrmaninfo() if network is None else node.getaddrmaninfo(network)
            assert_equal(result[-1], {"size: ": size})
            assert_equal(len(result) - 1, size)
            for entry in result[:-1]:
                assert_equal(entry, expected[entry['address']])
        # Card iQg6oeoK item 2: the size counts the entries the filter
        # left out; an unknown network name is not an error.
        assert_equal(node.getaddrmaninfo("ipv6"), [{"size: ": size}])
        assert_equal(node.getaddrmaninfo("foo"), [{"size: ": size}])
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", node.getaddrmaninfo, 5)
        assert_raises_rpc_error(-1, "getaddrmaninfo [networkType]", node.getaddrmaninfo, "ipv4", "ipv6")
        node.disconnect_p2ps()


if __name__ == '__main__':
    NetTest().main()
