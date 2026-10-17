#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the RPC HTTP server: connections, methods, auth, bodies and paths.

- Keep-alive: HTTP/1.1 keeps the connection, "Connection: close" closes
  it, HTTP/1.0 keeps it only with "Connection: keep-alive".
- Request size: a long URI gets 404, one beyond the header limit 400.
- Methods: only POST reaches the JSON-RPC handler (405 otherwise).
- Authorization: missing, other schemes and wrong credentials get 401
  with WWW-Authenticate; a 401 leaves a keep-alive connection usable.
- Bodies that aren't a JSON object or array get 500 "Parse error".
- A chunked request body is read.
- Paths: only "/" and "/wallet/<name>"; the reply echoes the request id.
"""

import http.client
import json
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, raw_rpc, rpc_port, str_to_b64str

AUTH = {'Authorization': 'Basic ' + str_to_b64str('yacoinuser:yacoinpwd')}


class HTTPBasicsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False

    def connection(self, http10=False):
        conn = http.client.HTTPConnection('127.0.0.1', rpc_port(0), timeout=30)
        if http10:
            conn._http_vsn = 10
            conn._http_vsn_str = 'HTTP/1.0'
        conn.connect()
        return conn

    def run_test(self):
        self.test_keep_alive()
        self.test_request_size()
        self.test_methods()
        self.test_auth()
        self.test_bodies()
        self.test_paths_and_ids()

    def test_keep_alive(self):
        self.log.info("HTTP/1.1 keeps the connection open")
        conn = self.connection()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', AUTH)
        assert b'"error":null' in conn.getresponse().read()
        assert conn.sock is not None
        conn.request('POST', '/', '{"method": "getchaintips"}', AUTH)
        assert b'"error":null' in conn.getresponse().read()
        assert conn.sock is not None
        conn.close()

        self.log.info("Connection: close closes it")
        conn = self.connection()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', dict(AUTH, Connection='close'))
        response = conn.getresponse()
        assert_equal(response.getheader('Connection'), 'close')
        assert b'"error":null' in response.read()
        assert conn.sock is None

        self.log.info("HTTP/1.0 keeps it only with Connection: keep-alive")
        conn = self.connection(http10=True)
        conn.request('POST', '/', '{"method": "getbestblockhash"}', dict(AUTH, Connection='keep-alive'))
        response = conn.getresponse()
        assert_equal(response.getheader('Connection'), 'keep-alive')
        assert b'"error":null' in response.read()
        assert conn.sock is not None
        conn.request('POST', '/', '{"method": "getchaintips"}', dict(AUTH, Connection='keep-alive'))
        assert b'"error":null' in conn.getresponse().read()
        assert conn.sock is not None
        conn.close()

        conn = self.connection(http10=True)
        conn.request('POST', '/', '{"method": "getbestblockhash"}', AUTH)
        assert b'"error":null' in conn.getresponse().read()
        assert conn.sock is None

    def test_request_size(self):
        self.log.info("A long URI gets 404, one beyond the header size limit 400")
        conn = self.connection()
        conn.request('GET', '/' + ('x' * 1000), '', AUTH)
        assert_equal(conn.getresponse().status, http.client.NOT_FOUND)
        conn = self.connection()
        conn.request('GET', '/' + ('x' * 10000), '', AUTH)
        assert_equal(conn.getresponse().status, http.client.BAD_REQUEST)
        # The limit (8192 bytes) covers all headers, not only the URI.
        conn = self.connection()
        conn.request('POST', '/', '{"method": "getblockcount"}', dict(AUTH, **{'X-Big': 'y' * 9000}))
        assert_equal(conn.getresponse().status, http.client.BAD_REQUEST)

    def test_methods(self):
        node = self.nodes[0]
        self.log.info("Only POST reaches the JSON-RPC handler")
        body = '{"method": "getblockcount"}'
        for method in ['GET', 'PUT']:
            assert_equal(raw_rpc(node, body, method=method)[::2], (405, b"JSONRPC server handles only POST requests"))
        # DELETE is rejected before any handler runs: no body.
        assert_equal(raw_rpc(node, body, method='DELETE')[::2], (405, b""))
        assert_equal(raw_rpc(node, '', method='HEAD')[0], 405)

    def test_auth(self):
        node = self.nodes[0]
        body = '{"method": "getblockcount"}'
        self.log.info("Missing or wrong authorization gets 401 with WWW-Authenticate")
        for headers in [
            {},
            {'Authorization': 'Bearer x'},
            # No colon in the credentials.
            {'Authorization': 'Basic ' + str_to_b64str('yacoinuser')},
            # The scheme is compared case-sensitively.
            {'Authorization': 'basic ' + str_to_b64str('yacoinuser:yacoinpwd')},
            {'Authorization': 'Basic ' + str_to_b64str('yacoinuser:wrong')},
        ]:
            status, reply_headers, reply = raw_rpc(node, body, auth=False, headers=headers)
            assert_equal((status, reply), (401, b""))
            assert_equal(reply_headers['WWW-Authenticate'], 'Basic realm="jsonrpc"')

        self.log.info("Spaces around the base64 credentials are trimmed")
        status, _, reply = raw_rpc(node, body, auth=False, headers={'Authorization': 'Basic   ' + str_to_b64str('yacoinuser:yacoinpwd') + '  '})
        assert_equal((status, json.loads(reply)['result']), (200, 0))

        self.log.info("A 401 leaves a keep-alive connection usable")
        conn = self.connection()
        conn.request('POST', '/', body, {'Authorization': 'Basic ' + str_to_b64str('a:b')})
        response = conn.getresponse()
        assert_equal((response.status, response.read()), (401, b""))
        assert conn.sock is not None
        conn.request('POST', '/', body, AUTH)
        response = conn.getresponse()
        assert_equal((response.status, json.loads(response.read())['result']), (200, 0))
        conn.close()

    def test_bodies(self):
        node = self.nodes[0]
        self.log.info("A body that isn't a JSON object or array gets a parse error")
        parse_error = {"result": None, "error": {"code": -32700, "message": "Parse error"}, "id": None}
        # A scalar top-level value is refused when reading the JSON already,
        # so it gets "Parse error" too.
        for body in ['{', '"x"', '1', 'null', '']:
            status, headers, reply = raw_rpc(node, body)
            assert_equal((status, json.loads(reply)), (500, parse_error))
            assert_equal(headers['Content-Type'], 'application/json')

        self.log.info("A chunked request body is read")
        sock = socket.create_connection(('127.0.0.1', rpc_port(0)), timeout=30)
        payload = b'{"method":"getblockcount","id":7}'
        sock.sendall(b'POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                     b'Authorization: ' + AUTH['Authorization'].encode() + b'\r\n'
                     b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n' +
                     b'%x\r\n' % len(payload) + payload + b'\r\n0\r\n\r\n')
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert_equal((response.status, json.loads(response.read())), (200, {"result": 0, "error": None, "id": 7}))
        sock.close()

    def test_paths_and_ids(self):
        node = self.nodes[0]
        self.log.info("Only / and /wallet/<name> are served")
        assert_equal(raw_rpc(node, '{"method": "getblockcount"}', path='/foo')[::2], (404, b""))
        # "/" is an exact match.
        assert_equal(raw_rpc(node, '{"method": "getblockcount"}', path='/?x=1')[::2], (404, b""))

        status, _, reply = raw_rpc(node, '{"method": "getwalletinfo"}', path='/wallet/wallet.dat')
        assert_equal((status, json.loads(reply)['result']['walletname']), (200, 'wallet.dat'))
        for path in ['/wallet/nope', '/wallet/']:
            status, _, reply = raw_rpc(node, '{"method": "getwalletinfo"}', path=path)
            assert_equal((status, json.loads(reply)['error']),
                         (500, {'code': -18, 'message': "Requested wallet does not exist or is not loaded"}))
        # Non-wallet methods don't look at the wallet path.
        status, _, reply = raw_rpc(node, '{"method": "getblockcount"}', path='/wallet/nope')
        assert_equal((status, json.loads(reply)['result']), (200, 0))

        self.log.info("The reply echoes the request id")
        for id_ in ['"s"', '5', 'null']:
            reply = json.loads(raw_rpc(node, '{"method": "getblockcount", "id": %s}' % id_)[2])
            assert_equal(reply['id'], json.loads(id_))
        assert_equal(json.loads(raw_rpc(node, '{"method": "getblockcount"}')[2])['id'], None)


if __name__ == '__main__':
    HTTPBasicsTest().main()
