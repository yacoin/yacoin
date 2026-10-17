#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the help RPC.

- The categories of help() on a default node, with -disablewallet (no
  wallet commands at all) and with -addressindex -tokenindex.
- Every listed command's help starts with its name.
- Hidden commands are not listed but have help.
- Unknown commands and too many arguments.
- Commands missing from help without their index, and a misspelt
  command name in the list (known failures).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

BASE_CATEGORIES = ['Blockchain', 'Control', 'Generating', 'Mining', 'Network', 'Rawtransactions', 'Tokens', 'Util']


def categories(node):
    return [line[3:-3] for line in node.help().split('\n') if line.startswith('== ')]


def listed_commands(node):
    return [line.split(' ')[0] for line in node.help().split('\n') if line and not line.startswith('==')]


class HelpRpcTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        # A fresh chain, so the indexes need no reindex.
        self.setup_clean_chain = True
        self.extra_args = [[], ['-disablewallet'], ['-addressindex=1', '-tokenindex=1']]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node, nowallet, indexed = self.nodes

        self.log.info("Categories")
        assert_equal(categories(node), BASE_CATEGORIES + ['Wallet'])
        assert_equal(categories(nowallet), BASE_CATEGORIES)
        assert_equal(categories(indexed), ['Addressindex'] + BASE_CATEGORIES + ['Wallet'])
        assert_equal(nowallet.help('getbalance'), 'help: unknown command: getbalance')
        assert_raises_rpc_error(-32601, "Method not found", nowallet.getbalance)

        self.log.info("Every listed command's help starts with its name")
        commands = listed_commands(indexed)
        assert 'getaddressbalance' in commands and 'listtokenbalancesbyaddress' in commands
        for command in commands:
            if command == 'calculateblockchash':
                continue
            assert indexed.help(command).split('\n')[0].startswith(command), command
        self.known_failure("uxP8YzbJ item 6",
                           lambda: assert_equal(node.help('calculateblockhash').split(' ')[0], 'calculateblockhash'),
                           expected="not(calculateblockchash == calculateblockhash)")

        self.log.info("Hidden commands have help but are not listed")
        for command in ['setmocktime', 'invalidateblock', 'waitfornewblock', 'waitforblock',
                        'waitforblockheight', 'logging', 'resendwallettransactions']:
            assert command not in commands
            assert node.help(command).startswith(command), command
        for command in ['echo', 'echojson']:
            assert command not in commands
            assert node.help(command).startswith('echo|echojson'), command

        self.log.info("Unknown commands and too many arguments")
        assert_equal(node.help('nonexistent'), 'help: unknown command: nonexistent')
        assert_raises_rpc_error(-1, 'help ( "command" )', node.help, 'a', 'b')

        self.log.info("Index commands have no help without their index")
        for command in ['getaddressbalance', 'listtokenbalancesbyaddress']:
            def check(command=command):
                text = node.help(command)
                assert text.startswith(command), text
            self.known_failure("gmPtMy1i item 2 (%s)" % command, check,
                               expected="help: unknown command: %s" % command)


if __name__ == '__main__':
    HelpRpcTest().main()
