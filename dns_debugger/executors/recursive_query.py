"""Test to target domain recursively"""
import random

from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.executors.testsuite import TestCase
from dns_debugger.query import dns_query
from dns_debugger.type import DataType
from dns_debugger.utils import split_qname


def run_tests(qname: str):
    """Run the test"""
    return [_recursive_query(qname=qname)]


def _recursive_query(qname: str) -> TestCase:
    """Make recursive queries"""
    nsserver_ip = None
    nsserver = None
    result = ''
    success = True
    for subqname in split_qname(qname):
        if nsserver:
            result += 'Getting NS record for {} from {}'.format(subqname, nsserver)
        else:
            result += 'Getting NS record for {}'.format(subqname)
        try:
            ns_records = dns_query(qname=subqname, rdtype=DataType.NS, origin=nsserver_ip)
            result += ' => {}\n'.format(','.join([ns.target for ns in ns_records.records]))
            nsserver = random.choice(ns_records.records).target
            nsserver_ips = dns_query(qname=nsserver, rdtype=DataType.A)
            nsserver_ip = random.choice(nsserver_ips.records).address
        except DnsDebuggerException as err:
            result += ' => {}'.format(err.message)
            success = False
            break

    return TestCase(description='Getting NS records recursively for {}'.format(qname), result=result, success=success)
