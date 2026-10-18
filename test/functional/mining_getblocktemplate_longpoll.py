#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getblocktemplate longpolls.

- A longpoll waits until the tip changes: a block from a peer, a block of
  the node itself, and the non-string longpollid (the current tip).
- A longpollid of an older tip returns at once.
- A longpollid shorter than a block hash: an error from the string library
  (known failure R-21).
- Stopping the node ends a waiting longpoll ("Shutting down", unless the
  connection closes first).

The waits that take a minute (a mempool change, a client that went away)
are in mining_getblocktemplate_longpoll_slow.py.
"""

import http.client
import threading

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy

BUG_CARD = "IvbXjqbT"


class LongpollThread(threading.Thread):
    """getblocktemplate(request) on its own RPC connection."""

    def __init__(self, node, request, timeout=60):
        super().__init__()
        self.proxy = get_rpc_proxy(node.url, node.index, timeout=timeout, coveragedir=node.coverage_dir)
        self.request = request
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.proxy.getblocktemplate(self.request)
        except Exception as e:
            self.error = e


class GetBlockTemplateLPTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def start_longpoll(self, node, request):
        """Start a longpoll thread and return it once the node handles the
        call (the nodes run with -debug)."""
        thread = LongpollThread(node, request)
        with node.assert_debug_log(["ThreadRPCServer method=getblocktemplate"], timeout=10):
            thread.start()
        return thread

    def assert_returns_on_new_tip(self, node, thread):
        thread.join(5)
        assert not thread.is_alive()
        assert_equal(thread.error, None)
        assert_equal(thread.result['previousblockhash'], node.getbestblockhash())

    @staticmethod
    def assert_short_longpollid_rejected(node):
        try:
            node.getblocktemplate({'longpollid': 'abc'})
        except JSONRPCException as e:
            assert e.error['code'] == -8, "error %d: %s" % (e.error['code'], e.error['message'])
            return
        raise AssertionError("No exception raised")

    def run_test(self):
        node = self.nodes[0]
        self.mine_with_mocktime(node, 10)

        self.log.info("A longpoll waits for a block from a peer")
        thread = LongpollThread(node, {'longpollid': node.getblocktemplate()['longpollid']})
        thread.start()
        thread.join(1)
        assert thread.is_alive()
        self.mine_with_mocktime(self.nodes[1], 1)
        self.assert_returns_on_new_tip(node, thread)

        self.log.info("... and for a block of the node itself")
        old_longpollid = node.getblocktemplate()['longpollid']
        thread = self.start_longpoll(node, {'longpollid': old_longpollid})
        self.mine_with_mocktime(node, 1)
        self.assert_returns_on_new_tip(node, thread)

        self.log.info("A non-string longpollid watches the current tip")
        thread = self.start_longpoll(node, {'longpollid': True})
        # The handler reads the tip it watches after the log line; a block
        # before that would make it wait a minute.
        thread.join(1)
        assert thread.is_alive()
        self.mine_with_mocktime(node, 1)
        self.assert_returns_on_new_tip(node, thread)

        self.log.info("A longpollid of an older tip returns at once")
        thread = LongpollThread(node, {'longpollid': old_longpollid})
        thread.start()
        self.assert_returns_on_new_tip(node, thread)

        self.log.info("A longpollid shorter than a block hash")
        self.known_failure("R-21 (%s)" % BUG_CARD,
                           lambda: self.assert_short_longpollid_rejected(node),
                           expected="error -1: basic_string::substr")

        self.log.info("Stopping the node ends a waiting longpoll")
        thread = self.start_longpoll(node, {'longpollid': node.getblocktemplate()['longpollid']})
        self.stop_node(0)
        thread.join(10)
        assert not thread.is_alive()
        # The answer races with the HTTP server shutting down: the client
        # gets it or a closed connection.
        if isinstance(thread.error, JSONRPCException):
            assert_equal(thread.error.error, {'code': -9, 'message': 'Shutting down'})
        else:
            assert isinstance(thread.error, (ConnectionError, http.client.HTTPException)), repr(thread.error)


if __name__ == '__main__':
    GetBlockTemplateLPTest().main()
