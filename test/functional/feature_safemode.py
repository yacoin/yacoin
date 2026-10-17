#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test safe mode (-testsafemode, -disablesafemode).

- With -testsafemode the warning shows in getinfo, getmininginfo and
  getnetworkinfo, RPCs not allowed in safe mode fail with -2, and the
  others still work.
- With -disablesafemode as well, the warning stays but every RPC works.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_is_hash_string, assert_raises_rpc_error

WARNING = "testsafemode enabled"


class SafeModeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        address = node.getnewaddress()
        txid = node.sendtoaddress(address=address, amount=1)
        raw = node.createrawtransaction([], {address: 1})

        self.log.info("-testsafemode: the warning is shown")
        self.restart_node(0, ['-testsafemode=1'])
        assert_equal(node.getinfo()['errors'], WARNING)
        assert_equal(node.getmininginfo()['errors'], WARNING)
        assert_equal(node.getnetworkinfo()['warnings'], WARNING)

        self.log.info("RPCs not allowed in safe mode fail")
        for call in [
            lambda: node.getbalance(),
            lambda: node.listunspent(),
            lambda: node.sendtoaddress(address=address, amount=1),
            lambda: node.signrawtransaction(raw),
            lambda: node.sendrawtransaction(raw),
            lambda: node.gettransaction(txid),
            lambda: node.getwalletinfo(),
            lambda: node.listtokenbalancesbyaddress(address),
        ]:
            assert_raises_rpc_error(-2, "Safe mode: " + WARNING, call)

        self.log.info("The others still work")
        height = node.getblockcount()
        assert_equal(node.getblock(node.getbestblockhash())['height'], height)
        assert_is_hash_string(node.generatetoaddress(1, address)[0])
        assert_equal(node.getblockcount(), height + 1)
        node.getnewaddress()

        self.log.info("-disablesafemode: everything works, the warning stays")
        self.restart_node(0, ['-testsafemode=1', '-disablesafemode=1'])
        assert_equal(node.getinfo()['errors'], WARNING)
        node.getbalance()
        assert len(node.listunspent()) > 0
        assert_equal(node.gettransaction(txid)['txid'], txid)
        assert_is_hash_string(node.sendtoaddress(address=address, amount=1))


if __name__ == '__main__':
    SafeModeTest().main()
