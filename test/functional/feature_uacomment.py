#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -uacomment option.

- The framework's comment appears in the subversion.
- The subversion may be 256 characters long, not 257.
- Comments with characters outside alphanumerics and " .,;-_?@" are
  refused; those characters are accepted.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal

MAX_SUBVERSION_LENGTH = 256


class UacommentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.log.info("The framework's comment is in the subversion")
        subversion = node.getnetworkinfo()["subversion"]
        assert subversion.endswith("(testnode0)/"), subversion

        self.log.info("test -uacomment max length")
        # The framework's comment comes first, then "; " and ours. The
        # base length depends on the version, so compute it.
        free = MAX_SUBVERSION_LENGTH - len(subversion) - len("; ")
        self.restart_node(0, ["-uacomment=" + "a" * free])
        assert_equal(len(node.getnetworkinfo()["subversion"]), MAX_SUBVERSION_LENGTH)
        self.stop_node(0)
        node.assert_start_raises_init_error(["-uacomment=" + "a" * (free + 1)],
            "Error: Total length of network version string (257) exceeds maximum length (256). Reduce the number or size of uacomments.",
            match=ErrorMatch.FULL_TEXT)
        node.assert_start_raises_init_error(["-uacomment=" + "a" * 256],
            r"Error: Total length of network version string \([0-9]+\) exceeds maximum length \(256\). Reduce the number or size of uacomments.",
            match=ErrorMatch.FULL_REGEX)

        self.log.info("test -uacomment unsafe characters")
        for unsafe_char in ['/', ':', '(', ')', '!', '<']:
            node.assert_start_raises_init_error(["-uacomment=a" + unsafe_char + "b"],
                "Error: User Agent comment (a%sb) contains unsafe characters." % unsafe_char,
                match=ErrorMatch.FULL_TEXT)

        self.log.info("test -uacomment safe characters")
        self.start_node(0, ["-uacomment=a .,;-_?@b"])
        assert node.getnetworkinfo()["subversion"].endswith("(testnode0; a .,;-_?@b)/")


if __name__ == '__main__':
    UacommentTest().main()
