#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the up-time field of getinfo.

The node formats its uptime as "N sec" below a minute, and as
"MM mins SS sec (N sec)", "HH hrs MM mins SS sec (N sec)" and
"D day(s) HH hrs MM mins SS sec (N sec)" above. Mocktime drives the clock,
so the test doesn't depend on how long the node took to start.
"""

import re
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class UptimeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def uptime_at(self, t):
        self.nodes[0].setmocktime(t)
        return self.nodes[0].getinfo()['up-time']

    def run_test(self):
        self.log.info("Find the node's start time from the uptime at a known mocktime")
        now = int(time.time())
        seconds = int(re.fullmatch(r'(\d+) sec', self.uptime_at(now)).group(1))
        # Both values are whole seconds, so this is the node's start time exactly.
        start = now - seconds
        assert_greater_than(59, seconds)

        self.log.info("Check each format, moving mocktime forward only")
        assert_equal(self.uptime_at(start + 59), "59 sec")
        assert_equal(self.uptime_at(start + 90), "01 mins 30 sec (90 sec)")
        assert_equal(self.uptime_at(start + 3600), "01 hrs 00 mins 00 sec (3600 sec)")
        assert_equal(self.uptime_at(start + 90100), "1 day 01 hrs 01 mins 40 sec (90100 sec)")
        assert_equal(self.uptime_at(start + 2 * 86400 + 3661), "2 days 01 hrs 01 mins 01 sec (176461 sec)")


if __name__ == '__main__':
    UptimeTest().main()
