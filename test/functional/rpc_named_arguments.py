#!/usr/bin/env python3
# Copyright (c) 2016-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test using named arguments for RPCs.

- Named arguments, an unknown name, an argument name with an alias
  (getblock's verbosity|verbose).
- Gaps between named arguments are filled with nulls, but not after the
  last one.

The checks use echojson, which yacoin-cli converts from JSON, so the
script also runs with --usecli and then tests the client's named
arguments.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class NamedArgumentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        h = node.help(command='getblockcount')
        assert h.startswith('getblockcount\n')

        assert_raises_rpc_error(-8, 'Unknown named parameter random', node.help, random='getblockcount')

        h = node.getblockhash(height=0)
        assert_equal(node.getblock(blockhash=h)['hash'], h)
        # verbose is an alias of verbosity.
        raw = node.getblock(h, 0)
        assert_equal(node.getblock(blockhash=h, verbose=False), raw)
        assert_equal(node.getblock(blockhash=h, verbosity=0), raw)

        assert_equal(node.echojson(), [])
        assert_equal(node.echojson(arg0=0, arg9=9), [0] + [None] * 8 + [9])
        assert_equal(node.echojson(arg1=1), [None, 1])
        assert_equal(node.echojson(arg9=None), [None] * 10)
        assert_equal(node.echojson(arg0=0, arg3=3, arg9=9), [0] + [None] * 2 + [3] + [None] * 5 + [9])


if __name__ == '__main__':
    NamedArgumentTest().main()
