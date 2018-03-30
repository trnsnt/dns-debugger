"""Make dnssec valirdation"""
import binascii
import random
from collections import defaultdict
from typing import Dict

from dns_debugger import LOGGER
from dns_debugger.dnssec.type import DS
from dns_debugger.dnssec.utils import verify_signed_dnskey_rrset
from dns_debugger.exceptions import DnsDebuggerException, QueryNoResponseException
from dns_debugger.executors.testsuite import TestCase
from dns_debugger.query import dns_query
from dns_debugger.type import DataType
from dns_debugger.utils import split_qname

TEST_DESCRIPTION = "Checking DNSSEC recursively for {}"


def run_tests(qname: str):
    """Run the test"""
    LOGGER.info("Verifying DNSSEC for qname %s", qname)
    chain_of_trust = {'DS': defaultdict(list), 'DNSKEY': {}}
    _add_root_to_chain_of_trust(cot=chain_of_trust)

    valid = True
    result = 'DNSSEC validation is OK'
    nsserver_ip = None
    try:
        for subqname in split_qname(qname=qname):

            ns_records = dns_query(qname=subqname, rdtype=DataType.NS, origin=nsserver_ip)
            nsserver = random.choice(ns_records.records).target
            nsserver_ips = dns_query(qname=nsserver, rdtype=DataType.A)
            nsserver_ip = random.choice(nsserver_ips.records).address

            if not _verify_cot(qname=subqname, chain_of_trust=chain_of_trust, origin=nsserver_ip):
                result = "There is no DNSSEC for this zone {}".format(subqname)
                break

            if subqname == 'qname':
                arecords = dns_query(qname=qname, rdtype=DataType.A, want_dnssec=True)
                arecords.is_valid(cot=chain_of_trust)
    except DnsDebuggerException as exc:
        valid = False
        result = exc.message
    return [TestCase(description=TEST_DESCRIPTION.format(qname), result=result, success=valid)]


def _add_root_to_chain_of_trust(cot: Dict[int, DS]):
    LOGGER.info("DS record 19036 is now in the chain of trust")
    cot['DS'][19036].append(DS(rdata=None, key_tag=19036, algorithm=8, digest_type=2,
                               digest=binascii.unhexlify(
                                   "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")))

    LOGGER.info("DS record 20326 is now in the chain of trust")
    cot['DS'][20326].append(DS(rdata=None, key_tag=20326, algorithm=8, digest_type=2,
                               digest=binascii.unhexlify(
                                   "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")))


def _verify_cot(qname: str, chain_of_trust, origin):
    LOGGER.info("Verifying chain of trust for qname %s", qname)
    if qname != ".":
        LOGGER.info("Get DS record for %s", qname)
        try:
            ds_records = dns_query(qname=qname, rdtype=DataType.DS, want_dnssec=True)
        except QueryNoResponseException:
            LOGGER.info("NO DS records found in parent zone, zone is not signed")
            return False

        is_valid = ds_records.is_valid(chain_of_trust)
        if not is_valid:
            message = "DS records received for {} are not valid (RRSIG not verified)".format(qname)
            raise DnsDebuggerException(message=message)
        for rec in ds_records.rrset.records:
            LOGGER.debug("Adding %s to the chain of trust", rec)
            chain_of_trust['DS'][rec.key_tag].append(rec)

    try:
        dnskeys = dns_query(qname=qname, rdtype=DataType.DNSKEY, want_dnssec=True, origin=origin)
    except QueryNoResponseException:
        raise DnsDebuggerException(
            message="Zone {} is not signed, there is no DNSKEY, but we have a parent DS record. "
                    "Please remove it".format(qname))
    LOGGER.info("Got %d DNSKEY", len(dnskeys.rrset.records))
    verify_signed_dnskey_rrset(rrset=dnskeys, cot=chain_of_trust, qname=qname)
    return True
