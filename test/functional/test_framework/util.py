#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for regression testing."""

from base64 import b64encode
from binascii import unhexlify
from decimal import Decimal, ROUND_DOWN
from subprocess import CalledProcessError
import hashlib
import hmac
import http.client
import inspect
import json
import logging
import os
import re
import time

from . import coverage
from .authproxy import AuthServiceProxy, JSONRPCException
from .netutil import all_interfaces

logger = logging.getLogger("TestFramework.utils")

# Assert functions
##################

def assert_approx(v, vexp, vspan=0.00001):
    """Assert that `v` is within `vspan` of `vexp`"""
    if v < vexp - vspan:
        raise AssertionError("%s < [%s..%s]" % (str(v), str(vexp - vspan), str(vexp + vspan)))
    if v > vexp + vspan:
        raise AssertionError("%s > [%s..%s]" % (str(v), str(vexp - vspan), str(vexp + vspan)))

def assert_contains(val, arr):
    if not (val in arr):
        raise AssertionError("val %s not in arr" % val)


def assert_does_not_contain(val, arr):
    if val in arr:
        raise AssertionError("val %s is in arr" % val)


def assert_contains_pair(key, val, dict_data):
    if not (key in dict_data and val == dict_data[key]):
        raise AssertionError("k/v pair (%s,%s) not in dict" % (key, val))


def assert_contains_key(key, dict_data):
    if key not in dict_data:
        raise AssertionError("key %s is not in dict" % key)

def assert_does_not_contain_key(key, dict_data):
    if key in dict_data:
        raise AssertionError("key %s is in dict" % key)

def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args))

def assert_greater_than(thing1, thing2):
    if thing1 <= thing2:
        raise AssertionError("%s <= %s" % (str(thing1), str(thing2)))

def assert_greater_than_or_equal(thing1, thing2):
    if thing1 < thing2:
        raise AssertionError("%s < %s" % (str(thing1), str(thing2)))

def assert_raises(exc, fun, *args, **kwds):
    assert_raises_message(exc, None, fun, *args, **kwds)

def assert_raises_message(exc, message, fun, *args, **kwds):
    try:
        fun(*args, **kwds)
    except JSONRPCException:
        raise AssertionError("Use assert_raises_rpc_error() to test RPC failures")
    except exc as e:
        if message is not None and message not in e.error['message']:
            raise AssertionError(
                "Expected substring not found in error message:\nsubstring: '{}'\nerror message: '{}'.".format(
                    message, e.error['message']))
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " + type(e).__name__)
    else:
        raise AssertionError("No exception raised")

def assert_raises_process_error(returncode, output, fun, *args, **kwds):
    """Execute a process and asserts the process return code and output.

    Calls function `fun` with arguments `args` and `kwds`. Catches a CalledProcessError
    and verifies that the return code and output are as expected. Throws AssertionError if
    no CalledProcessError was raised or if the return code and output are not as expected.

    Args:
        returncode (int): the process return code.
        output (string): [a substring of] the process output.
        fun (function): the function to call. This should execute a process.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    try:
        fun(*args, **kwds)
    except CalledProcessError as e:
        if returncode != e.returncode:
            raise AssertionError("Unexpected returncode %i" % e.returncode)
        if output not in e.output:
            raise AssertionError("Expected substring not found:" + e.output)
    else:
        raise AssertionError("No exception raised")

def assert_raises_rpc_error(code, message, fun, *args, **kwds):
    """Run an RPC and verify that a specific JSONRPC exception code and message is raised.

    Calls function `fun` with arguments `args` and `kwds`. Catches a JSONRPCException
    and verifies that the error code and message are as expected. Throws AssertionError if
    no JSONRPCException was raised or if the error code/message are not as expected.

    Args:
        code (int), optional: the error code returned by the RPC call (defined
            in src/rpc/protocol.h). Set to None if checking the error code is not required.
        message (string), optional: [a substring of] the error string returned by the
            RPC call. Set to None if checking the error string is not required.
        fun (function): the function to call. This should be the name of an RPC.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    assert try_rpc(code, message, fun, *args, **kwds), "No exception raised"

def try_rpc(code, message, fun, *args, **kwds):
    """Tries to run an rpc command.

    Test against error code and message if the rpc fails.
    Returns whether a JSONRPCException was raised."""
    try:
        fun(*args, **kwds)
    except JSONRPCException as e:
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        if (code is not None) and (code != e.error["code"]):
            raise AssertionError("Unexpected JSONRPC error code %i" % e.error["code"])
        if (message is not None) and (message not in e.error['message']):
            raise AssertionError(
                "Expected substring not found in error message:\nsubstring: '{}'\nerror message: '{}'.".format(
                    message, e.error['message']))
        return True
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " + type(e).__name__)
    else:
        return False

def read_block_file(path, magic, checksum_size=0):
    """Read a blk*.dat or rev*.dat file.

    Returns its content and the (offset, size) of each record: the network
    magic, a 4-byte little-endian size, size bytes of data, then
    checksum_size bytes (32 in rev*.dat). Stops at the zero padding."""
    with open(path, 'rb') as f:
        data = f.read()
    records = []
    pos = 0
    while pos + 8 <= len(data) and data[pos:pos + 4] == magic:
        size = int.from_bytes(data[pos + 4:pos + 8], 'little')
        records.append((pos, size))
        pos += 8 + size + checksum_size
    return data, records

def known_failure(log, bug, check, expected):
    """Run an assertion that a known bug breaks today.

    Passes (and logs) while check() fails the way the bug makes it fail, and
    raises as soon as the check passes, so the marker is removed together with
    the fix. `bug` names the bug and its Trello card, e.g. "W-B5 (XbGM5oTW)".

    `expected` is the bug's symptom and is required, so that an unrelated
    failure (a typo in an RPC name, a stopped node, a timeout) isn't taken for
    the bug: a substring or a compiled regex that must be found in the
    AssertionError's text or the JSONRPCException's message, or an int that
    must equal the JSONRPCException's error code. Any other failure is raised
    unchanged, after logging that it isn't the expected known failure."""
    try:
        check()
    except (AssertionError, JSONRPCException) as e:
        rpc_error = isinstance(e, JSONRPCException)
        text = e.error.get('message', '') if rpc_error else str(e)
        if isinstance(expected, int):
            matched = rpc_error and e.error.get('code') == expected
        elif hasattr(expected, 'search'):
            matched = expected.search(text) is not None
        else:
            matched = expected in text
        if not matched:
            log.error("%s: this failure is not the expected known failure (expected %r)" % (bug, getattr(expected, 'pattern', expected)))
            raise
        log.info("Known failure %s: %s" % (bug, e))
        return
    raise AssertionError("%s no longer fails; remove the known-failure marker" % bug)

def assert_is_hex_string(string):
    try:
        int(string, 16)
    except Exception as e:
        raise AssertionError(
            "Couldn't interpret %r as hexadecimal; raised: %s" % (string, e))

def assert_is_hash_string(string, length=64):
    if not isinstance(string, str):
        raise AssertionError("Expected a string, got type %r" % type(string))
    elif length and len(string) != length:
        raise AssertionError(
            "String of length %d expected; got %d" % (length, len(string)))
    elif not re.match('[abcdef0-9]+$', string):
        raise AssertionError(
            "String %r contains invalid characters for a hash." % string)

def assert_array_result(object_array, to_match, expected, should_not_find=False):
    """
        Pass in array of JSON objects, a dictionary with key/value pairs
        to match against, and another dictionary with expected key/value
        pairs.
        If the should_not_find flag is true, to_match should not be found
        in object_array
        """
    if should_not_find:
        assert_equal(expected, {})
    num_matched = 0
    for item in object_array:
        all_match = True
        for key, value in to_match.items():
            if item[key] != value:
                all_match = False
        if not all_match:
            continue
        elif should_not_find:
            num_matched = num_matched + 1
        for key, value in expected.items():
            if item[key] != value:
                raise AssertionError("%s : expected %s=%s" % (str(item), str(key), str(value)))
            num_matched = num_matched + 1
    if num_matched == 0 and not should_not_find:
        raise AssertionError("No objects matched %s" % (str(to_match)))
    if num_matched > 0 and should_not_find:
        raise AssertionError("Objects were found %s" % (str(to_match)))

# Utility functions
###################

def check_json_precision():
    """Make sure json library being used does not lose precision converting BTC values"""
    n = Decimal("20000000.00000003")
    satoshis = int(json.loads(json.dumps(float(n))) * 1.0e8)
    if satoshis != 2000000000000003:
        raise RuntimeError("JSON encode/decode loses precision")

def EncodeDecimal(o):
    if isinstance(o, Decimal):
        return str(o)
    raise TypeError(repr(o) + " is not JSON serializable")

def count_bytes(hex_string):
    return len(bytearray.fromhex(hex_string))


def hex_str_to_bytes(hex_str):
    return unhexlify(hex_str.encode('ascii'))

def str_to_b64str(string):
    return b64encode(string.encode('utf-8')).decode('ascii')

def satoshi_round(amount):
    """Round down to YACoin's smallest unit (6 decimals)."""
    return Decimal(amount).quantize(Decimal('0.000001'), rounding=ROUND_DOWN)

def wait_until(predicate, *, attempts=float('inf'), timeout=float('inf'), lock=None):
    if attempts == float('inf') and timeout == float('inf'):
        timeout = 60
    attempt = 0
    time_end = time.time() + timeout

    while attempt < attempts and time.time() < time_end:
        if lock:
            with lock:
                if predicate():
                    return
        else:
            if predicate():
                return
        attempt += 1
        time.sleep(0.05)

    # Print the cause of the timeout
    predicate_source = "''''\n" + inspect.getsource(predicate) + "'''"
    logger.error("wait_until() failed. Predicate: {}".format(predicate_source))
    if attempt >= attempts:
        raise AssertionError("Predicate {} not true after {} attempts".format(predicate_source, attempts))
    elif time.time() >= time_end:
        raise AssertionError("Predicate {} not true after {} seconds".format(predicate_source, timeout))
    raise RuntimeError('Unreachable')

# RPC/P2P connection constants and functions
############################################

# The maximum number of nodes a single test can spawn
MAX_NODES = 12
# Don't assign rpc or p2p ports lower than this
PORT_MIN = int(os.getenv('TEST_RUNNER_PORT_MIN', default=11000))
# The number of ports to "reserve" for p2p and rpc, each
PORT_RANGE = 5000


class PortSeed:
    # Must be initialized with a unique integer for each process
    n = None

def get_rpc_proxy(url, node_number, *, timeout=None, coveragedir=None):
    """
    Args:
        url (str): URL of the RPC server to call
        node_number (int): the node number (or id) that this calls to

    Kwargs:
        timeout (int): HTTP timeout in seconds
        coveragedir (str): Directory

    Returns:
        AuthServiceProxy. convenience object for making RPC calls.

    """
    proxy_kwargs = {}
    if timeout is not None:
        proxy_kwargs['timeout'] = timeout

    proxy = AuthServiceProxy(url, **proxy_kwargs)
    proxy.url = url  # store URL on proxy for info

    coverage_logfile = coverage.get_filename(
        coveragedir, node_number) if coveragedir else None

    return coverage.AuthServiceProxyWrapper(proxy, coverage_logfile)

def p2p_port(n):
    assert n <= MAX_NODES
    return PORT_MIN + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)

def rpc_port(n):
    return PORT_MIN + PORT_RANGE + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)

def rpc_url(datadir, i, chain, rpchost):
    rpc_u, rpc_p = get_auth_cookie(datadir, chain)
    host = '127.0.0.1'
    port = rpc_port(i)
    if rpchost:
        parts = rpchost.split(':')
        if len(parts) == 2:
            host, port = parts
        else:
            host = rpchost
    return "http://%s:%s@%s:%d" % (rpc_u, rpc_p, host, int(port))

# Node functions
################

def initialize_datadir(dirname, n, chain, epochinterval=10):
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    # Translate chain name to config name
    if chain == 'testnet3':
        chain_name_conf_arg = 'testnet'
        chain_name_conf_section = 'test'
    else:
        chain_name_conf_arg = chain
        chain_name_conf_section = chain
    with open(os.path.join(datadir, "yacoin.conf"), 'w', encoding='utf8') as f:
        # f.write("{}=1\n".format(chain_name_conf_arg))
        # f.write("[{}]\n".format(chain_name_conf_section))
        f.write("rpcuser=yacoinuser\n")
        f.write("rpcpassword=yacoinpwd\n")
        f.write("port=" + str(p2p_port(n)) + "\n")
        f.write("rpcport=" + str(rpc_port(n)) + "\n")
        f.write("checkblocks=8\n")
        f.write("server=1\n")
        f.write("daemon=0\n")
        f.write("debug=1\n")
        f.write("logtimestamps=1\n")
        f.write("epochinterval="+ str(epochinterval) +"\n")
        # f.write("keypool=1\n")
        # f.write("discover=0\n")
        f.write("dnsseed=0\n")
        f.write("printtoconsole=0\n")
        f.write("upnp=0\n")
        f.write("nFactorAtHardfork=4\n")
        # f.write("shrinkdebugfile=0\n")
        os.makedirs(os.path.join(datadir, 'stderr'), exist_ok=True)
        os.makedirs(os.path.join(datadir, 'stdout'), exist_ok=True)
    return datadir

def get_datadir_path(dirname, n):
    return os.path.join(dirname, "node" + str(n))

def append_config(datadir, options):
    with open(os.path.join(datadir, "yacoin.conf"), 'a', encoding='utf8') as f:
        for option in options:
            f.write(option + "\n")

def get_auth_cookie(datadir, chain):
    user = None
    password = None
    if os.path.isfile(os.path.join(datadir, "yacoin.conf")):
        with open(os.path.join(datadir, "yacoin.conf"), 'r', encoding='utf8') as f:
            for line in f:
                if line.startswith("rpcuser="):
                    assert user is None  # Ensure that there is only one rpcuser line
                    user = line.split("=")[1].strip("\n")
                if line.startswith("rpcpassword="):
                    assert password is None  # Ensure that there is only one rpcpassword line
                    password = line.split("=")[1].strip("\n")
    try:
        with open(os.path.join(datadir, chain, ".cookie"), 'r', encoding="ascii") as f:
            userpass = f.read()
            split_userpass = userpass.split(':')
            user = split_userpass[0]
            password = split_userpass[1]
    except OSError:
        pass
    if user is None or password is None:
        raise ValueError("No RPC credentials")
    return user, password

# If a cookie file exists in the given datadir, delete it.
def delete_cookie_file(datadir, chain):
    if os.path.isfile(os.path.join(datadir, chain, ".cookie")):
        logger.debug("Deleting leftover cookie file")
        os.remove(os.path.join(datadir, chain, ".cookie"))

def rpcauth_value(user, password, salt=None):
    """Return the value of an -rpcauth option for user and password:
    "user:salt$hash", hash = HMAC-SHA256(key=salt as text, msg=password),
    as httprpc.cpp checks it. Use as "-rpcauth=" + rpcauth_value(...)."""
    if salt is None:
        salt = os.urandom(16).hex()
    digest = hmac.new(salt.encode('utf-8'), password.encode('utf-8'), hashlib.sha256).hexdigest()
    return "{}:{}${}".format(user, salt, digest)

def raw_rpc(node, body, *, method='POST', path='/', headers=None, auth=True):
    """Send one HTTP request to node's RPC server and return
    (status, headers, body bytes), without interpreting the response.

    body: bytes or str as is; anything else is sent as JSON. auth: True uses
    the node's configured credentials, a (user, password) pair those, and
    False sends no Authorization header. For checking HTTP status codes,
    non-JSON bodies and raw JSON (e.g. duplicate keys)."""
    if isinstance(body, str):
        body = body.encode('utf-8')
    elif not isinstance(body, bytes):
        body = json.dumps(body, default=EncodeDecimal).encode('utf-8')
    all_headers = {'Content-Type': 'application/json'}
    if auth:
        user, password = get_auth_cookie(node.datadir, node.chain) if auth is True else auth
        all_headers['Authorization'] = 'Basic ' + str_to_b64str('{}:{}'.format(user, password))
    all_headers.update(headers or {})
    conn = http.client.HTTPConnection('127.0.0.1', rpc_port(node.index), timeout=60)
    try:
        conn.request(method, path, body, all_headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()

def non_loopback_ipv4():
    """Return the first IPv4 address of a non-loopback interface, or None."""
    for _, addr in all_interfaces():
        if not addr.startswith('127.'):
            return addr
    return None

def softfork_active(node, key):
    """Return whether a softfork is active."""
    return node.getblockchaininfo()['softforks'][key]['active']

def set_node_times(nodes, t):
    for node in nodes:
        node.setmocktime(t)

def disconnect_nodes(from_connection, node_num):
    for peer_id in [peer['id'] for peer in from_connection.getpeerinfo() if peer.get('subver') and "testnode%d" % node_num in peer.get('subver')]:
        try:
            from_connection.disconnectnode(nodeid=peer_id)
        except JSONRPCException as e:
            # If this node is disconnected between calculating the peer id
            # and issuing the disconnect, don't worry about it.
            # This avoids a race condition if we're mass-disconnecting peers.
            if e.error['code'] != -29: # RPC_CLIENT_NODE_NOT_CONNECTED
                raise

    # wait to disconnect
    wait_until(lambda: [peer['id'] for peer in from_connection.getpeerinfo() if peer.get('subver') and "testnode%d" % node_num in peer.get('subver')] == [], timeout=5)

def peers(node):
    """Return getpeerinfo() without the trailing {"size: ": n} element YACoin appends."""
    return [peer for peer in node.getpeerinfo() if 'id' in peer]

def connect_nodes(from_connection, node_num):
    ip_port = "127.0.0.1:" + str(p2p_port(node_num))
    from_connection.addnode(ip_port, "onetry")
    # Wait until both sides have finished the version handshake, so that
    # transactions created next are relayed. A node sends its first ping only
    # after it got the peer's verack, and its own verack went out before that
    # on the same connection; the peer answers the ping only after processing
    # that verack. So a pong on our outbound connection means both sides are
    # done.
    def handshake_done():
        return any(peer['addr'] == ip_port and not peer['inbound'] and peer['version'] != 0
                   and 'pong' in peer['bytesrecv_per_msg'] for peer in peers(from_connection))
    wait_until(handshake_done)

def sync_blocks(rpc_connections, *, wait=0.1, timeout=60):
    """
    Wait until everybody has the same tip.

    sync_blocks needs to be called with an rpc_connections set that has least
    one node already synced to the latest, stable tip, otherwise there's a
    chance it might return before all nodes are stably synced.
    """
    stop_time = time.time() + timeout
    while time.time() <= stop_time:
        best_hash = [x.getbestblockhash() for x in rpc_connections]
        if best_hash.count(best_hash[0]) == len(rpc_connections):
            return
        time.sleep(wait)
    # A node without peers is the usual cause; say so in the message.
    peer_counts = [len(peers(x)) for x in rpc_connections]
    raise AssertionError("Block sync timed out (peer count of each node: {}):{}".format(
        peer_counts, "".join("\n  {!r}".format(b) for b in best_hash)))

def sync_mempools(rpc_connections, *, wait=0.1, timeout=60):
    """
    Wait until everybody has the same transactions in their memory
    pools
    """
    stop_time = time.time() + timeout
    while time.time() <= stop_time:
        pool = set(rpc_connections[0].getrawmempool())
        num_match = 1
        for i in range(1, len(rpc_connections)):
            if set(rpc_connections[i].getrawmempool()) == pool:
                num_match = num_match + 1
        if num_match == len(rpc_connections):
            return
        time.sleep(wait)
    raise AssertionError("Mempool sync failed")

# Transaction/Block functions
#############################

def find_output(node, txid, amount, *, blockhash=None):
    """
    Return index to output of txid with value amount
    Raises exception if there is none.
    """
    txdata = node.getrawtransaction(txid, 1, blockhash)
    for i in range(len(txdata["vout"])):
        if txdata["vout"][i]["value"] == amount:
            return i
    raise RuntimeError("find_output txid %s : %s not found" % (txid, str(amount)))

def find_vout_for_address(node, txid, addr):
    """
    Locate the vout index of the given transaction sending to the
    given address. Raises runtime error exception if not found.
    """
    tx = node.getrawtransaction(txid, True)
    for i in range(len(tx["vout"])):
        if any([addr == a for a in tx["vout"][i]["scriptPubKey"]["addresses"]]):
            return i
    raise RuntimeError("Vout not found for address: txid=%s, addr=%s" % (txid, addr))
