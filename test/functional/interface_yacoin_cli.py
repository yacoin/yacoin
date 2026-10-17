#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test yacoin-cli and yacoind's command-line RPC mode.

- Version, usage and the "too few parameters" errors.
- Results equal the RPC's (getinfo); wrong credentials; RPC errors become
  "error code/message" and the exit code is the error code.
- -stdin, -named, echojson conversion and its parse errors.
- -rpcwait, -rpcconnect (with and without a port), -rpcport, a closed
  port, -rpcclienttimeout, -rpcssl, -testnet with -regtest, -rpcwallet.
- yacoind <command> sends the command like yacoin-cli.
- Arguments the client converts differently from what the server reads
  (known failures).
"""

import os
import socket
import subprocess
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hash_string,
    assert_raises_process_error,
    assert_raises_rpc_error,
    rpc_port,
)


class TestBitcoinCli(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # It compares yacoin-cli with the RPC interface itself.
        self.supports_cli = False
        # Tokens active from the start, for the reissue argument check.
        self.extra_args = [['-tokenSupportBlockNumber=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()

    def run_binary(self, binary, *args, input=None):
        """Run binary with the node's datadir; return (exit code, stdout, stderr)."""
        p = subprocess.run([binary, '-datadir=' + self.nodes[0].datadir] + list(args), input=input,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
        return p.returncode, p.stdout, p.stderr

    def run_test(self):
        node = self.nodes[0]
        cli = node.cli
        self.cli_binary = self.options.bitcoincli

        self.log.info("Version, usage and missing commands")
        assert cli('-version').send_cli().startswith("Yacoin Core RPC client version")
        for option in ['-?', '-help']:
            rc, out, _ = self.run_binary(self.cli_binary, option)
            assert_equal(rc, 0)
            assert 'Usage:' in out and '-rpcconnect=<ip>' in out
        assert_raises_process_error(1, "error: too few parameters (need at least command)", cli.send_cli)
        p = subprocess.run([self.cli_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert_equal((p.returncode, p.stderr), (1, "Error: too few parameters\n"))

        self.log.info("Results equal the RPC's")
        cli_info = cli.getinfo()
        rpc_info = node.getinfo()
        del cli_info['up-time'], rpc_info['up-time']
        assert_equal(cli_info, rpc_info)

        self.log.info("Wrong credentials")
        for option in ['-rpcpassword=wrong', '-rpcuser=wrong']:
            assert_raises_process_error(1, "error: incorrect rpcuser or rpcpassword (authorization failed)", cli(option).getblockcount)

        self.log.info("RPC errors: message and exit code")
        assert_raises_rpc_error(-8, "Block height out of range", cli.getblockhash, 1000)
        assert_equal(self.run_binary(self.cli_binary, 'getblockhash', '1000'),
                     (8, '', "error code: -8\nerror message:\nBlock height out of range\n"))
        assert_raises_rpc_error(-32601, "Method not found", cli.nosuchmethod)
        assert_raises_process_error(1, "error: Error parsing JSON:abc", cli.getblockhash, 'abc')

        self.log.info("-stdin, -named and argument conversion")
        assert_equal(cli('-stdin', input='a\nb').echo(), ['a', 'b'])
        assert_equal(cli.echo(arg1='x'), [None, 'x'])
        assert_raises_process_error(1, "error: No '=' in named argument 'arg1', this needs to be present for every argument (even if it is empty)",
                                    cli('-named').echo, 'arg1')
        assert_raises_rpc_error(-8, "Unknown named parameter nope", cli.echo, nope=1)
        assert_equal(cli.echojson('{"a":1}', '[1,2]', 'true', 'null', '1.5'), [{'a': 1}, [1, 2], True, None, Decimal('1.5')])
        assert_raises_process_error(1, "error: Error parsing JSON:{bad", cli.echojson, '{bad')

        self.log.info("Connection options")
        height = node.getblockcount()
        assert_equal(cli('-rpcconnect=127.0.0.1', '-rpcport=%d' % rpc_port(0)).getblockcount(), height)
        # A socket that is bound but doesn't listen: connections are refused,
        # and no other test can get this port meanwhile.
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
        assert_raises_process_error(1, "error: couldn't connect to server: unknown (code -1)", cli('-rpcport=%d' % closed_port).getblockcount)
        # The port in -rpcconnect is used only without -rpcport, which
        # yacoin.conf sets: use a copy of it without that line.
        with open(os.path.join(node.datadir, 'yacoin.conf'), encoding='utf8') as f:
            conf = [l for l in f.read().splitlines() if not l.startswith('rpcport=')]
        with open(os.path.join(node.datadir, 'cli.conf'), 'w', encoding='utf8') as f:
            f.write('\n'.join(conf) + '\n')
        assert_equal(cli('-conf=cli.conf', '-rpcconnect=127.0.0.1:%d' % rpc_port(0)).getblockcount(), height)
        assert_raises_process_error(1, "error: couldn't connect to server", cli('-conf=cli.conf', '-rpcconnect=127.0.0.1:%d' % closed_port).getblockcount)
        closed.close()
        assert_raises_process_error(1, "error: couldn't connect to server: timeout reached (code 0)",
                                    cli('-rpcclienttimeout=1').waitfornewblock, 3000)
        assert_raises_process_error(1, "Error: SSL mode for RPC (-rpcssl) is no longer supported.", cli('-rpcssl=1').getblockcount)
        assert_raises_process_error(1, "Error: Invalid combination of -regtest and -testnet.", cli('-testnet=1', '-regtest=1').getblockcount)

        self.log.info("-rpcwallet")
        assert_equal(cli('-rpcwallet=wallet.dat').getwalletinfo()['walletname'], 'wallet.dat')
        assert_raises_rpc_error(-18, "Requested wallet does not exist or is not loaded", cli('-rpcwallet=nope').getwalletinfo)

        self.log.info("yacoind <command> works like yacoin-cli")
        assert_equal(self.run_binary(self.options.bitcoind, 'getblockcount'), (0, '%d\n' % height, ''))
        assert_equal(self.run_binary(self.options.bitcoind, 'getblockhash', '1000'),
                     (8, '', "error code: -8\nerror message:\nBlock height out of range\n"))

        self.log.info("-rpcwait waits for the server")
        self.stop_node(0)
        node.start()
        assert_equal(cli('-rpcwait').getblockcount(), height)
        node.wait_for_rpc_connection()

        self.test_conversions()

    def test_conversions(self):
        node = self.nodes[0]
        cli = node.cli
        address = node.getnewaddress()

        self.log.info("getsubsidy takes the nBits as a string")
        # A JSON string written out passes today.
        assert_equal(cli.getsubsidy('"1e0fffff"'), node.getsubsidy('1e0fffff'))

        def subsidy():
            try:
                assert_equal(cli.getsubsidy('1e0fffff'), node.getsubsidy('1e0fffff'))
            except subprocess.CalledProcessError as e:
                raise AssertionError(e.output)
        self.known_failure("uxP8YzbJ item 3 (getsubsidy)", subsidy, expected="Error parsing JSON:1e0fffff")

        self.log.info("sendmany's useexpiredtimelockutxo by name")
        # The cached chain's coins are in the "coinbase" account.
        assert_is_hash_string(cli.sendmany('coinbase', {address: 1}, False))
        self.known_failure("uxP8YzbJ item 3 (sendmany)",
                           lambda: assert_is_hash_string(cli.sendmany(fromaccount='coinbase', amounts={address: 1}, useexpiredtimelockutxo=False)),
                           expected="JSON value is not a boolean as expected")

        self.log.info("reissue's new_units by name")
        # Positionally the arguments get through, to the missing token.
        assert_raises_rpc_error(-25, "doesn't exist in the database", cli.reissue, 'NOPE', 1, True, address, '', 2)

        def reissue():
            try:
                cli.reissue(token_name='NOPE', qty=1, reissuable=True, to_address=address, change_address='', new_units=2)
            except JSONRPCException as e:
                if e.error['code'] == -25 and "doesn't exist in the database" in e.error['message']:
                    return
                raise
            raise AssertionError("reissue of a missing token succeeded")
        self.known_failure("uxP8YzbJ item 3 (reissue)", reissue, expected="JSON value is not an integer as expected")


if __name__ == '__main__':
    TestBitcoinCli().main()
