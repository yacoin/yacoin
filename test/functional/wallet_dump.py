#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dumpwallet and importwallet RPCs.

- dumpwallet of an unencrypted and of an encrypted wallet: every address,
  label, change and reserve key, the HD master key, and the P2SH section with
  the CLTV/CSV redeem scripts and their keys (also checked against
  dumpprivkey).
- Errors: an existing or unwritable target file, a missing import file, and
  a locked wallet; a relative path is resolved against the node's working
  directory.
- importwallet of the dump on a second node restores the keys. Known
  failure W-B2: it restores no labels and no redeem scripts.
- Known failure W-B1: dumpwallet aborts the node when the wallet holds a
  redeem script whose key it doesn't have (a multisig script, or a CLTV
  script of another wallet). Run last, on node 1.
"""
import http.client
import os
import re

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

P2SH_HEADER = "# BELOW ARE LIST OF P2SH ADDRESSES"
LOCKED = "Error: Please enter the wallet passphrase with walletpassphrase first."


def read_dump(file_name, addrs, hd_master_addr_old):
    """
    Read the P2PKH section of the given dump, count the addrs that match,
    count change and reserve. Also check that the old hd_master is inactive
    """
    with open(file_name, encoding='utf8') as inputfile:
        found_addr = 0
        found_addr_chg = 0
        found_addr_rsv = 0
        hd_master_addr_ret = None
        for line in inputfile:
            if line.startswith(P2SH_HEADER):
                break
            # only read non comment lines
            if line[0] != "#" and len(line) > 10:
                # split out some data
                key_label, comment = line.split("#")
                # key = key_label.split(" ")[0]
                keytype = key_label.split(" ")[2]
                if len(comment) > 1:
                    addr_keypath = comment.split(" addr=")[1]
                    addr = addr_keypath.split(" ")[0]
                    keypath = None
                    if keytype == "inactivehdmaster=1":
                        # ensure the old master is still available
                        assert(hd_master_addr_old == addr)
                    elif keytype == "hdmaster=1":
                        # ensure we have generated a new hd master key
                        assert(hd_master_addr_old != addr)
                        hd_master_addr_ret = addr
                    else:
                        keypath = addr_keypath.rstrip().split("hdkeypath=")[1]

                    # count key types
                    for addrObj in addrs:
                        if addrObj['address'] == addr and addrObj['hdkeypath'] == keypath and keytype == "label=":
                            found_addr += 1
                            break
                        elif keytype == "change=1":
                            found_addr_chg += 1
                            break
                        elif keytype == "reserve=1":
                            found_addr_rsv += 1
                            break
        return found_addr, found_addr_chg, found_addr_rsv, hd_master_addr_ret


def read_p2sh(file_name):
    """Return the lines of the dump's P2SH section."""
    with open(file_name, encoding='utf8') as f:
        lines = f.read().split('\n')
    start = [i for i, line in enumerate(lines) if line.startswith(P2SH_HEADER)]
    assert_equal(len(start), 1)
    section = []
    for line in lines[start[0] + 1:]:
        if line == "":
            break
        section.append(line)
    return section


class WalletDumpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-keypool=90"], []]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

    def run_test(self):
        node0, node1 = self.nodes
        wallet_unenc_dump = os.path.join(node0.datadir, "wallet.unencrypted.dump")
        wallet_enc_dump = os.path.join(node0.datadir, "wallet.encrypted.dump")

        # generate 20 addresses to compare against the dump
        test_addr_count = 20
        addrs = []
        for i in range(0,test_addr_count):
            addr = node0.getnewaddress()
            vaddr= node0.validateaddress(addr) #required to get hd keypath
            addrs.append(vaddr)

        # Labelled addresses and timelock scripts. Created before the
        # keypoolrefill so the reserve count stays at 90 + 90.
        labelled = {label: node0.getnewaddress(label) for label in ('l1', 'l2', 'l3')}
        cl = node0.createcltvaddress(1000, 'cl')
        cs = node0.createcsvaddress(10, True, 'cs')
        scripts = {
            cl['cltv address']: ('CLTV_P2SH_timelock', 'cl', cl['redeemScript']),
            cs['csv address']: ('CSV_P2SH_timelock', 'cs', cs['redeemScript']),
        }

        # Should be a no-op:
        node0.keypoolrefill()

        self.log.info("Dump the unencrypted wallet")
        result = node0.dumpwallet(wallet_unenc_dump)
        assert_equal(result['filename'], wallet_unenc_dump)

        found_addr, found_addr_chg, found_addr_rsv, hd_master_addr_unenc = \
            read_dump(wallet_unenc_dump, addrs, None)
        assert_equal(found_addr, test_addr_count)  # all keys must be in the dump
        # no blocks were mined; the keys of the two timelock scripts have no
        # address book entry and are written as change
        assert_equal(found_addr_chg, 2)
        assert_equal(found_addr_rsv, 90*2) # 90 keys plus 100% internal keys

        with open(wallet_unenc_dump, encoding='utf8') as f:
            dump_lines = f.read().split('\n')
        for label, address in labelled.items():
            lines = [line for line in dump_lines if ' # addr=%s ' % address in line]
            assert_equal(len(lines), 1)
            assert_equal(lines[0].split(' ')[2], 'label=' + label)

        self.log.info("Check the P2SH section of the dump")
        p2sh_lines = read_p2sh(wallet_unenc_dump)
        assert_equal(len(p2sh_lines), 2)
        for line in p2sh_lines:
            m = re.match(r'^(\S+) type=(\S+) label=(\S+) redeemscript=([0-9a-f]+) # addr=(\S+)$', line)
            assert m, line
            wif, script_type, label, redeem_script, address = m.groups()
            assert_equal((script_type, label, redeem_script), scripts[address])
            privkey = node0.dumpprivkey(address)
            assert_equal(privkey, {'address_type': 'P2SH address', 'private_key': wif, 'redeem_script': redeem_script})
            # The same key is in the P2PKH section, under the key's own address
            key_address = node0.validateaddress(address)['addresses'][0]
            key_lines = [l for l in dump_lines if l.startswith(wif + ' ') and ' # addr=%s ' % key_address in l]
            assert_equal(len(key_lines), 1)
            assert_equal(key_lines[0].split(' ')[2], 'change=1')

        self.log.info("Check dump and import errors")
        missing_dir = os.path.join(self.options.tmpdir, 'nonexistent', 'wallet.dump')
        assert_raises_rpc_error(-4, "Error dumping wallet keys to file", node0.dumpwallet, missing_dir)
        # Misleading message for a missing file (W-B16)
        assert_raises_rpc_error(-4, "Error adding some keys to wallet", node1.importwallet, missing_dir)
        # A relative path is relative to the node's working directory (the test's tmpdir)
        result = node0.dumpwallet('relative.dump')
        assert_equal(result['filename'], os.path.join(self.options.tmpdir, 'relative.dump'))
        assert os.path.isfile(result['filename'])

        self.log.info("Import the dump on node 1")
        assert_equal(node1.importwallet(wallet_unenc_dump), None)
        for address in labelled.values():
            assert node1.validateaddress(address)['ismine']
            assert_equal(node1.dumpprivkey(address), node0.dumpprivkey(address))
        # The keys of the timelock scripts arrive (as change keys); the scripts
        # themselves don't (W-B2 below)
        for address in scripts:
            key_address = node0.validateaddress(address)['addresses'][0]
            assert node1.validateaddress(key_address)['ismine']
            assert_equal(node1.dumpprivkey(key_address), node0.dumpprivkey(key_address))

        def check_labels_and_scripts():
            # Sorted, so the first failing label (the marker's symptom) is the same on Python 3.5
            for label, address in sorted(labelled.items()):
                assert_equal(node1.getaccount(address), label)
            for address, (_, label, redeem_script) in scripts.items():
                info = node1.validateaddress(address)
                assert_equal((info['ismine'], info.get('account'), info.get('hex')), (True, label, redeem_script))
                assert_equal(node1.getaddressesbyaccount(label), [address])
        # importwallet never leaves its start state (it waits for '@' section
        # headers; dumpwallet writes '#'), so labels, key times and scripts
        # are not restored.
        self.known_failure("W-B2 (FrgyyrOz)", check_labels_and_scripts, expected="not( == l1)")

        # encrypt wallet, restart, unlock and dump
        node0.encryptwallet('test')
        node0.wait_until_stopped()
        self.start_node(0)

        self.log.info("Dump and import need an unlocked wallet")
        assert_raises_rpc_error(-13, LOCKED, node0.dumpwallet, wallet_enc_dump)
        assert_raises_rpc_error(-13, LOCKED, node0.importwallet, wallet_unenc_dump)

        node0.walletpassphrase('test', 100)
        # Should be a no-op:
        node0.keypoolrefill()
        node0.dumpwallet(wallet_enc_dump)

        found_addr, found_addr_chg, found_addr_rsv, hd_master_addr_enc = \
            read_dump(wallet_enc_dump, addrs, hd_master_addr_unenc)
        assert_equal(found_addr, test_addr_count)
        assert_equal(found_addr_chg, 90*2 + 2)  # old reserve keys are marked as change now
        assert_equal(found_addr_rsv, 90*2)
        assert_equal(len(read_p2sh(wallet_enc_dump)), 2)

        # Overwriting should fail
        assert_raises_rpc_error(-8, "already exists", lambda: node0.dumpwallet(wallet_enc_dump))

        self.test_dump_keyless_scripts()

    def test_dump_keyless_scripts(self):
        """W-B1: redeem scripts whose key the wallet doesn't have."""
        self.log.info("Dump a wallet with redeem scripts it has no key for")
        # A clean restart first, so the coverage data of node 1's earlier work
        # is written; an abort skips that.
        self.restart_node(1)
        node0, node1 = self.nodes
        multisig = node1.addmultisigaddress(1, [node1.getnewaddress()])
        foreign_cltv = node0.createcltvaddress(2000)
        node1.addredeemscript(foreign_cltv['redeemScript'])
        path = os.path.join(node1.datadir, 'keyless.dump')
        crashed = False
        error = None
        try:
            node1.dumpwallet(path)
        except JSONRPCException as e:
            error = e
        except (OSError, http.client.HTTPException):
            # Today the node aborts in CBitcoinSecret::SetKey
            assert_equal(node1.wait_for_exit(), -6)
            assert "Assertion `vchSecret.IsValid()' failed." in node1.read_stderr(), node1.read_stderr()
            crashed = True
            self.start_node(1)
            assert node1.validateaddress(multisig)['ismine']

        def check_dump():
            assert not crashed, "dumpwallet aborted the node"
            assert error is None, "dumpwallet failed: %s" % error
            with open(path, encoding='utf8') as f:
                assert f.read().endswith("# End of dump\n")
            node1.getblockcount()
        self.known_failure("W-B1 (JFXNhpEp)", check_dump, expected="dumpwallet aborted the node")


if __name__ == '__main__':
    WalletDumpTest().main()
