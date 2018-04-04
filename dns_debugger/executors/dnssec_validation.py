"""Make dnssec valirdation"""
import random

from dns_debugger import LOGGER
from dns_debugger.dnssec.utils import verify_dnskey_rrset, get_and_check_parent_ds
from dns_debugger.exceptions import DnsDebuggerException, QueryNoResponseException
from dns_debugger.executors.testsuite import TestCase
from dns_debugger.models import Resolver, ChainOfTrust
from dns_debugger.query import dns_query
from dns_debugger.records_models import DataType
from dns_debugger.utils import split_qname

TEST_DESCRIPTION = "Checking DNSSEC recursively for {}"


def run_tests(qname: str):
    """Run the test"""
    LOGGER.info("Verifying DNSSEC for qname %s", qname)
    chain_of_trust = ChainOfTrust()
    valid = True
    result = 'DNSSEC validation is OK'
    resolver = Resolver()

    try:
        for subqname in split_qname(qname=qname):
            LOGGER.info("Checking DNSSEC for %s", subqname)

            ns_records = dns_query(qname=subqname, rdtype=DataType.NS, origin=resolver)
            resolver = Resolver(qname=random.choice(ns_records.records).target)

            if not _check_qname(qname=subqname, chain_of_trust=chain_of_trust, origin=resolver):
                result = "There is no DNSSEC for this zone {}".format(subqname)
                break

            if subqname == 'qname':
                arecords = dns_query(qname=qname, rdtype=DataType.A, want_dnssec=True)
                arecords.is_valid(cot=chain_of_trust)
    except DnsDebuggerException as exc:
        valid = False
        result = exc.message
    return [TestCase(description=TEST_DESCRIPTION.format(qname), result=result, success=valid)]


def _check_qname(qname: str, chain_of_trust, origin):
    LOGGER.info("Verifying chain of trust for qname %s", qname)

    is_dnssec_activated = get_and_check_parent_ds(qname=qname, chain_of_trust=chain_of_trust)
    if not is_dnssec_activated:
        return is_dnssec_activated

    try:
        dnskeys = dns_query(qname=qname, rdtype=DataType.DNSKEY, want_dnssec=True, origin=origin)
    except QueryNoResponseException:
        raise DnsDebuggerException(
            message="Zone {} is not signed, there is no DNSKEY, but we have a parent DS record. "
                    "Please remove DS record or sign the zone".format(qname))
    LOGGER.info("Got %d DNSKEY", len(dnskeys.records))
    LOGGER.debug(dnskeys)

    verify_dnskey_rrset(rrset=dnskeys, cot=chain_of_trust, qname=qname)
    return True
