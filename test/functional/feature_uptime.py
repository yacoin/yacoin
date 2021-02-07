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
        test_start_time = test_start_time - seconds_0 # this is the real start time

        assert(seconds_0 < 40) # should be quick, since we don't have any blockchain data
        time.sleep(10)
        uptime = self.nodes[0].getinfo()['up-time']
        self.log.info('10 secs later '+str(uptime))
        seconds_1 = int(re.match('(\d\d) sec',uptime).groups()[0])
        assert(seconds_1-seconds_0 == 10 or seconds_1-seconds_0 == 11) # give it some slack

        # works with mocktime to test minutes
        self.nodes[0].setmocktime(test_start_time + 90)
        uptime = self.nodes[0].getinfo()['up-time']
        self.log.info('With mocktime 1:30 minutes: '+str(uptime))
        matches = re.match('(\d\d) mins (\d\d) sec \((\d\d) sec\)',uptime).groups()
        assert_equal(int(matches[0]), 1) # minutes
        assert_equal(int(matches[1]), 30) # seconds
        assert_equal(int(matches[2]), 90) # total seconds
        
        # test hours
        self.nodes[0].setmocktime(test_start_time + 3600)
        uptime = self.nodes[0].getinfo()['up-time']
        self.log.info('With mocktime 1 hour: '+str(uptime))
        matches = re.match('(\d\d) hrs (\d\d) mins (\d\d) sec \((\d\d\d\d) sec\)',uptime).groups()
        assert_equal(int(matches[0]), 1) # hours
        assert_equal(int(matches[1]), 0) # minutes
        assert_equal(int(matches[2]), 0) # seconds
        assert_equal(int(matches[3]), 3600) # total seconds
        
        # test days
        self.nodes[0].setmocktime(test_start_time + 90100)
        uptime = self.nodes[0].getinfo()['up-time']
        self.log.info('With mocktime 1 day: '+str(uptime))
        matches = re.match('(\d) day (\d\d) hrs (\d\d) mins (\d\d) sec \((\d\d\d\d\d) sec\)',uptime).groups()
        assert_equal(int(matches[0]), 1) # days
        assert_equal(int(matches[1]), 1) # hours
        assert_equal(int(matches[2]), 1) # minutes
        assert_equal(int(matches[3]), 40) # seconds
        assert_equal(int(matches[4]), 90100) # total seconds

if __name__ == '__main__':
    UptimeTest().main()
