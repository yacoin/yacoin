#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getblocktemplate longpoll waits that take a minute.

- A mempool change without a new block ends a longpoll after a minute
  (real time; mocktime doesn't shorten it).
- A client that closed its connection doesn't keep the HTTP worker: with
  -rpcthreads=1 the node answers the next call once the longpoll wakes up
  and notices, a minute after the call (not at the next block).
"""

import base64
import json
import socket
import time
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, connect_nodes, get_rpc_proxy

from mining_getblocktemplate_longpoll import LongpollThread


class GetBlockTemplateLPSlowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.mine_with_mocktime(node, 10)

        self.log.info("A mempool change ends a longpoll after a minute")
        tip = node.getbestblockhash()
        thread = LongpollThread(node, {'longpollid': node.getblocktemplate()['longpollid']}, timeout=120)
        with node.assert_debug_log(["ThreadRPCServer method=getblocktemplate"], timeout=10):
            thread.start()
        start = time.time()
        node.sendtoaddress(self.nodes[1].getnewaddress(), 1)
        thread.join(90)
        assert not thread.is_alive()
        assert_greater_than(time.time() - start, 50)
        assert_equal(thread.error, None)
        assert_equal(thread.result['previousblockhash'], tip)
        # Confirm the transaction: a mempool change would also end the next
        # wait after a minute, client or no client.
        self.mine_with_mocktime(node, 1)

        self.log.info("A client that went away doesn't keep the only HTTP worker")
        self.restart_node(0, ['-rpcthreads=1'])
        assert_equal(node.getrawmempool(), [])
        # getblocktemplate needs a peer
        connect_nodes(self.nodes[1], 0)
        # a string longpollid with the current mempool counter (a non-string
        # one uses the counter of the last template, none in this process)
        longpollid = node.getblocktemplate()['longpollid']
        url = urllib.parse.urlparse(node.url)
        body = json.dumps({'method': 'getblocktemplate', 'params': [{'longpollid': longpollid}], 'id': 1})
        auth = base64.b64encode(("%s:%s" % (url.username, url.password)).encode()).decode()
        request = ("POST / HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n"
                   "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                   % (url.hostname, auth, len(body), body))
        with node.assert_debug_log(["ThreadRPCServer method=getblocktemplate"], timeout=10):
            sock = socket.create_connection((url.hostname, url.port))
            sock.sendall(request.encode())
        # no answer within a second: the longpoll waits
        sock.settimeout(1)
        try:
            sock.recv(1)
            raise AssertionError("the longpoll answered at once")
        except socket.timeout:
            pass
        start = time.time()
        sock.close()
        # queues behind the longpoll on the single worker
        proxy = get_rpc_proxy(node.url, node.index, timeout=120, coveragedir=node.coverage_dir)
        assert_equal(proxy.getblockcount(), node.getblockcount())
        elapsed = time.time() - start
        self.log.info("answered after %.1f s", elapsed)
        # the first wake-up, a minute after the call
        assert 50 < elapsed < 75, elapsed


if __name__ == '__main__':
    GetBlockTemplateLPSlowTest().main()
