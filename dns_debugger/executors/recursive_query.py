"""Test to target domain recursively"""
import random
from typing import Tuple

from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.executors.testsuite import TestCase, TestStep, TestStatus
from dns_debugger.query import dns_query, Resolver
from dns_debugger.records_models import DataType
from dns_debugger.utils import split_qname


def run_tests(qname: str):
    """Run the test"""
    return [_recursive_query(qname=qname)]


def _recursive_query(qname: str) -> TestCase:
    """Make recursive queries"""
    resolver = Resolver()
    testcase = TestCase(description='Getting NS records recursively for {}'.format(qname))
    for subqname in split_qname(qname):
        teststep, resolver = _query_ns(qname=subqname, resolver=resolver)
        testcase.add_step(teststep)
        if testcase.status == TestStatus.ERROR:
            break

        if subqname == qname:
            # For last iteration, we check if we can received A record
            teststep = _query_a(qname=subqname, resolver=resolver)
            testcase.add_step(teststep)

    return testcase


def _query_ns(qname: str, resolver: Resolver) -> Tuple[TestStep, Resolver]:
    description = 'Getting NS record for {} from {}'.format(qname, resolver)
    new_resolver = None
    try:
        ns_records = dns_query(qname=qname, rdtype=DataType.NS, resolver=resolver)
        if ns_records.rdtype != DataType.NS.value:
            result = "No NS entry for {}".format(qname)
            status = TestStatus.ERROR
        else:
            result = ', '.join([ns.target for ns in ns_records.records])
            status = TestStatus.SUCCESS
            new_resolver = Resolver(qname=random.choice(ns_records.records).target)
    except DnsDebuggerException as err:
        result = err.message
        status = TestStatus.ERROR
    return TestStep(description=description, result=result, status=status), new_resolver


def _query_a(qname: str, resolver: Resolver) -> TestStep:
    description = 'Getting A record for {} from {}'.format(qname, resolver)
    try:
        arecords = dns_query(qname=qname, rdtype=DataType.A, resolver=resolver)
        result = ', '.join([arecord.address for arecord in arecords.records])
        status = TestStatus.SUCCESS
    except DnsDebuggerException as err:
        result = err.message
        status = TestStatus.ERROR

    return TestStep(description=description, result=result, status=status)
