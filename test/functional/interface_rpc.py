#!/usr/bin/env python3
# Copyright (c) 2018-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generic aspects of the JSON-RPC interface.

- getrpcinfo: its keys, the active command, log path and RPC port.
- Batch requests: every kind of invalid element gets its own error object
  in order, and an empty batch gives an empty list.
- Single requests: invalid request objects give HTTP 400, an unknown method
  404, other errors 500; an unknown named parameter is refused.
- uptime with a parameter (known failure).
- The HTTP work queue: with -rpcworkqueue=1 -rpcthreads=1 a request that
  finds the queue full gets HTTP 500 "Work queue depth exceeded".
"""

import json
import os
import threading

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    raw_rpc,
    rpc_port,
    rpc_url,
    wait_until,
)


def expect_http_status(expected_http_status, expected_rpc_code,
                       fcn, *args):
    try:
        fcn(*args)
        raise AssertionError("Expected RPC error %d, got none" % expected_rpc_code)
    except JSONRPCException as exc:
        assert_equal(exc.error["code"], expected_rpc_code)
        assert_equal(exc.http_status, expected_http_status)


def rpc_reply(node, body):
    """(HTTP status, decoded JSON reply) of one raw request."""
    status, _, reply = raw_rpc(node, body)
    return status, json.loads(reply.decode('utf-8'))


class RPCInterfaceTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False

    def test_getrpcinfo(self):
        self.log.info("Testing getrpcinfo...")

        info = self.nodes[0].getrpcinfo()
        assert_equal(sorted(info), ['RPCport', 'active_commands', 'logpath'])
        assert_equal(len(info['active_commands']), 1)

        command = info['active_commands'][0]
        assert_equal(command['method'], 'getrpcinfo')
        assert_greater_than_or_equal(command['duration'], 0)
        assert_equal(info['logpath'], os.path.join(self.nodes[0].datadir, 'debug.log'))
        # A number, not a string.
        assert_equal(info['RPCport'], rpc_port(0))

    def test_batch_request(self):
        self.log.info("Testing basic JSON-RPC batch request...")

        results = self.nodes[0].batch([
            # A basic request that will work fine.
            {"method": "getblockcount", "id": 1},
            # Request that will fail.  The whole batch request should still
            # work fine.
            {"method": "invalidmethod", "id": 2},
            # Another call that should succeed.
            {"method": "getbestblockhash", "id": 3},
        ])

        result_by_id = {}
        for res in results:
            result_by_id[res["id"]] = res

        assert_equal(result_by_id[1]['error'], None)
        assert_equal(result_by_id[1]['result'], 0)

        assert_equal(result_by_id[2]['error']['code'], -32601)
        assert_equal(result_by_id[2]['result'], None)

        assert_equal(result_by_id[3]['error'], None)
        assert result_by_id[3]['result'] is not None

    def test_batch_invalid_elements(self):
        self.log.info("Testing invalid batch elements...")
        node = self.nodes[0]
        status, replies = rpc_reply(node, '[1, {"id": 1}, {"method": 1, "id": 2}, '
                                          '{"method": "getblockcount", "params": "x", "id": 3}, '
                                          '{"method": "getblockcount", "id": 4}, '
                                          '{"method": "nosuchmethod", "id": 5}, '
                                          '{"method": "getblockhash", "params": ["a"], "id": 6}, []]')
        assert_equal(status, 200)
        expected = [
            (None, -32600, "Invalid Request object"),
            (1, -32600, "Missing method"),
            (2, -32600, "Method must be a string"),
            (3, -32600, "Params must be an array or object"),
            (4, None, None),
            (5, -32601, "Method not found"),
            (6, -1, "JSON value is not an integer as expected"),
            (None, -32600, "Invalid Request object"),
        ]
        assert_equal(len(replies), len(expected))
        for reply, (id_, code, message) in zip(replies, expected):
            assert_equal(reply['id'], id_)
            if code is None:
                assert_equal((reply['result'], reply['error']), (0, None))
            else:
                assert_equal(reply['result'], None)
                assert_equal((reply['error']['code'], reply['error']['message']), (code, message))

        assert_equal(rpc_reply(node, '[]'), (200, []))

    def test_http_status_codes(self):
        self.log.info("Testing HTTP status codes for JSON-RPC requests...")
        node = self.nodes[0]

        expect_http_status(404, -32601, node.invalidmethod)
        expect_http_status(500, -8, node.getblockhash, 42)

        # Invalid request objects map to 400.
        for body, message in [
            ('{"id": 1}', "Missing method"),
            ('{"method": 1, "id": 1}', "Method must be a string"),
            ('{"method": "getblockcount", "params": "x", "id": 1}', "Params must be an array or object"),
        ]:
            status, reply = rpc_reply(node, body)
            assert_equal(status, 400)
            assert_equal(reply['error'], {'code': -32600, 'message': message})
            assert_equal(reply['id'], 1)

        # params null is the same as no params.
        assert_equal(rpc_reply(node, '{"method": "getblockcount", "params": null, "id": 1}'),
                     (200, {'result': 0, 'error': None, 'id': 1}))

        status, reply = rpc_reply(node, '{"method": "help", "params": {"random": "x"}, "id": 1}')
        assert_equal(status, 500)
        assert_equal(reply['error'], {'code': -8, 'message': "Unknown named parameter random"})

    def test_uptime_params(self):
        self.log.info("uptime takes no parameter")
        node = self.nodes[0]
        self.known_failure("uxP8YzbJ item 6, uptime arg",
                           lambda: assert_raises_rpc_error(-1, "uptime", node.uptime, 1),
                           expected="No exception raised")

    def test_work_queue_exceeded(self):
        self.log.info("Testing work queue exceeded...")
        self.restart_node(0, ['-rpcworkqueue=1', '-rpcthreads=1'])
        node = self.nodes[0]
        debug_log = os.path.join(node.datadir, 'debug.log')
        with open(debug_log, 'rb') as f:
            f.seek(0, 2)
            log_start = f.tell()

        def log_since_start():
            with open(debug_log, 'rb') as f:
                f.seek(log_start)
                return f.read().decode('utf-8', 'replace')

        url = rpc_url(node.datadir, 0, node.chain, None)
        results = {}

        def call(name, method, *args):
            results[name] = getattr(get_rpc_proxy(url, 0, timeout=60), method)(*args)

        # A holds the only worker thread. No RPC can check that (it would
        # wait in the queue), so watch the debug log.
        thread_a = threading.Thread(target=call, args=('a', 'waitfornewblock', 2000))
        thread_a.start()
        wait_until(lambda: 'ThreadRPCServer method=waitfornewblock' in log_since_start())
        received = log_since_start().count('Received a POST request for / from')
        # B fills the queue. The HTTP thread logs a request just before it
        # queues it, and handles requests in order, so once B's line is in
        # the log, B is queued before the next request is read.
        thread_b = threading.Thread(target=call, args=('b', 'getblockcount'))
        thread_b.start()
        wait_until(lambda: log_since_start().count('Received a POST request for / from') > received)

        status, _, body = raw_rpc(node, '{"method": "getblockcount", "id": 1}')
        assert_equal((status, body), (500, b"Work queue depth exceeded"))
        assert 'WARNING: request rejected because http work queue depth exceeded, it can be increased with the -rpcworkqueue= setting' in log_since_start()

        thread_a.join()
        thread_b.join()
        assert_equal(results, {'a': {'hash': node.getbestblockhash(), 'height': 0}, 'b': 0})
        assert_equal(node.getblockcount(), 0)

    def run_test(self):
        self.test_getrpcinfo()
        self.test_batch_request()
        self.test_batch_invalid_elements()
        self.test_http_status_codes()
        self.test_uptime_params()
        self.test_work_queue_exceeded()


if __name__ == '__main__':
    RPCInterfaceTest().main()
