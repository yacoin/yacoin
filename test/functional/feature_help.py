#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that starting yacoind with -h and --version works as expected.

The help text misses RPC server options and still lists the removed
-rpcssl ones (known failure).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Options yacoind has, and removed ones (-rpcssl only makes startup fail).
SHOULD_BE_LISTED = ['-rpcauth=', '-rpcbind=', '-rpcthreads=', '-alertnotify=']
# Core lists these only with -help-debug.
SHOULD_BE_LISTED_DEBUG = ['-rpcworkqueue=', '-rpcservertimeout=', '-testsafemode', '-disablesafemode']
SHOULD_NOT_BE_LISTED = ['-rpcssl\n', '-rpcsslcertificatechainfile=', '-rpcsslprivatekeyfile=', '-rpcsslciphers=']

class HelpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        # Don't start the node

    def get_node_output(self, *, ret_code_expected):
        ret_code = self.nodes[0].process.wait(timeout=60)
        assert_equal(ret_code, ret_code_expected)
        self.nodes[0].stdout.seek(0)
        self.nodes[0].stderr.seek(0)
        out = self.nodes[0].stdout.read()
        err = self.nodes[0].stderr.read()
        self.nodes[0].stdout.close()
        self.nodes[0].stderr.close()

        # Clean up TestNode state
        self.nodes[0].running = False
        self.nodes[0].process = None
        self.nodes[0].rpc_connected = False
        self.nodes[0].rpc = None

        return out, err

    def run_test(self):        
        self.log.info("Start bitcoin with -h for help text")
        self.nodes[0].start(extra_args=['-h'])
        # Node should exit immediately and output help to stdout.
        output, _ = self.get_node_output(ret_code_expected=0)
        assert b'Options' in output
        self.log.info("Help text received: {} (...)".format(output[0:60]))
        text = output.decode('utf-8')
        self.nodes[0].start(extra_args=['-h', '-help-debug'])
        debug_text = self.get_node_output(ret_code_expected=0)[0].decode('utf-8')

        def check():
            missing = [o for o in SHOULD_BE_LISTED if o not in text]
            missing += [o for o in SHOULD_BE_LISTED_DEBUG if o not in debug_text]
            removed = [o for o in SHOULD_NOT_BE_LISTED if o in text]
            assert_equal((missing, removed), ([], []))
        self.known_failure("uxP8YzbJ item 7", check, expected="'-rpcauth=', '-rpcbind='")

        self.log.info("Start bitcoin with -version for version information")
        self.nodes[0].start(extra_args=['--version'])
        # Node should exit immediately and output version to stdout.
        output, _ = self.get_node_output(ret_code_expected=0)
        assert b'version' in output
        self.log.info("Version text received: {} (...)".format(output[0:60]))
        # # Test that arguments not in the help results in an error
        # self.log.info("Start bitcoind with -fakearg to make sure it does not start")
        # self.nodes[0].start(extra_args=['-fakearg'])
        # # Node should exit immediately and output an error to stderr
        # _, output = self.get_node_output(ret_code_expected=1)
        # assert b'Error parsing command line arguments' in output
        # self.log.info("Error message received: {} (...)".format(output[0:60]))


if __name__ == '__main__':
    HelpTest().main()
