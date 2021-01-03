#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that uptime is reported as expected."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
import time
import re

class UptimeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False


    def run_test(self):
        test_start_time = int(time.time())
        uptime_start = self.nodes[0].getinfo()['up-time']
        self.log.info('After start '+str(uptime_start))
        seconds_0 = int(re.match('(\d\d) sec',uptime_start).groups()[0])
        assert(seconds_0 < 40) # should be quick, since we don't have any blockchain data
        time.sleep(10)
        uptime = self.nodes[0].getinfo()['up-time']
        self.log.info('10 secs later '+str(uptime))
        seconds_1 = int(re.match('(\d\d) sec',uptime).groups()[0])
        assert(seconds_1-seconds_0 == 10 or seconds_1-seconds_0 == 1) # give it some slack

if __name__ == '__main__':
    UptimeTest().main()
