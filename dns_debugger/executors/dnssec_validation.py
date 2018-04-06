"""Make dnssec valirdation"""
import random
from typing import Tuple, List

from dns_debugger import LOGGER
from dns_debugger.exceptions import DnsDebuggerException, QueryNoResponseException
from dns_debugger.executors.testsuite import TestCase, TestStep, TestStatus
from dns_debugger.models import ChainOfTrust
from dns_debugger.query import dns_query, Resolver
from dns_debugger.records_models import DataType, RRSet
from dns_debugger.utils import split_qname

TEST_DESCRIPTION = "Checking DNSSEC recursively for {}"


def run_tests(qname: str):
    """Run the test"""
    LOGGER.info("Verifying DNSSEC for qname %s", qname)
    chain_of_trust = ChainOfTrust()
    resolver = Resolver()
    testcase = TestCase(description=TEST_DESCRIPTION.format(qname))

    try:
        for subqname in split_qname(qname=qname):
            steps, resolver = check_dnssec_for_qname(qname=subqname, chain_of_trust=chain_of_trust,
                                                     resolver=resolver)
            testcase.add_steps(steps=steps)
            if testcase.status.value > TestStatus.SUCCESS.value:
                return [testcase]

            if qname == subqname:
                teststep = _query_check_rrsig(qname=qname, datatype=DataType.A, chain_of_trust=chain_of_trust,
                                              resolver=resolver)
                testcase.add_step(step=teststep)
    except DnsDebuggerException as err:
        testcase.add_step(
            step=TestStep(description="Unexpected Error during dnssec validation", result=err.message,
                          status=TestStatus.ERROR))
    return [testcase]


def check_dnssec_for_qname(qname, chain_of_trust, resolver) -> Tuple[List[TestStep], Resolver]:
    """Check DNSSEC for a given qname"""
    LOGGER.info("Checking DNSSEC for %s", qname)
    steps = []
    try:
        ns_records = dns_query(qname=qname, rdtype=DataType.NS, resolver=resolver)
        resolver = Resolver(qname=random.choice(ns_records.records).target)
    except DnsDebuggerException as err:
        teststep = TestStep(description="Get NS server for {}".format(qname), status=TestStatus.ERROR,
                            result=err.message)
        steps.append(teststep)
        return steps, resolver

    if qname != ".":
        testscases = _get_and_check_ds(qname=qname, chain_of_trust=chain_of_trust)
        steps = steps + testscases
        if any([tc.status.value > TestStatus.SUCCESS.value for tc in testscases]):
            return steps, resolver

    testscases = _get_and_check_dnskey(qname=qname, resolver=resolver, chain_of_trust=chain_of_trust)
    steps = steps + testscases
    if any([tc.status.value > TestStatus.SUCCESS.value for tc in testscases]):
        return steps, resolver

    return steps, resolver


def _get_and_check_ds(qname, chain_of_trust) -> List[TestStep]:
    """Get and check DS record for a qname"""
    steps = []
    teststep, dsrecord_rrset = _get_ds_record(qname)
    steps.append(teststep)
    if teststep.status.value > TestStatus.SUCCESS.value:
        return steps

    teststep = _check_ds_rrset(dsrrset=dsrecord_rrset, chain_of_trust=chain_of_trust, qname=qname)
    steps.append(teststep)
    return steps


def _get_and_check_dnskey(qname, resolver, chain_of_trust) -> List[TestStep]:
    """Get and check DNSKEY for a qname"""
    steps = []
    teststep, dnskeys = _get_dnskeys(qname=qname, resolver=resolver)
    steps.append(teststep)
    if teststep.status == TestStatus.ERROR:
        return steps

    teststeps = _validate_dnskeys_via_ds(dnskeyrrset=dnskeys, qname=qname, chain_of_trust=chain_of_trust)
    error_found = False
    for teststep in teststeps:
        steps.append(teststep)
        if teststep.status == TestStatus.ERROR:
            error_found = True
    if error_found:
        return steps

    teststep = _check_rrsig(qname=qname, dnskeys=dnskeys, chain_of_trust=chain_of_trust)
    steps.append(teststep)
    return steps


def _query_check_rrsig(qname, datatype, chain_of_trust, resolver):
    """Make a query and check if RRSIG is valid"""
    description = "Check if {dtype} records for {qname} are DNSSEC valid".format(dtype=datatype.name, qname=qname)
    try:
        arecords = dns_query(qname=qname, rdtype=DataType.A, want_dnssec=True, resolver=resolver)

        if not arecords.is_valid(chain_of_trust):
            result = "{dtype} records received for {qname} are not valid (RRSIG not verified)".format(
                dtype=datatype.name, qname=qname)
            status = TestStatus.ERROR
        else:
            status = TestStatus.SUCCESS
            result = "Records received {} valid through RRSIG".format(arecords)

    except DnsDebuggerException as err:
        status = TestStatus.ERROR
        result = err.message

    return TestStep(description=description, status=status, result=result)


def _get_ds_record(qname) -> Tuple[TestStep, RRSet]:
    """Get DS record for a given domain*"""
    description = "Get DS record for {}".format(qname)
    LOGGER.info(description)
    try:
        ds_records = dns_query(qname=qname, rdtype=DataType.DS, want_dnssec=True)
        status = TestStatus.SUCCESS
        result = str(ds_records)
    except DnsDebuggerException as err:
        status = TestStatus.ERROR
        result = err.message
        ds_records = None

    if status == TestStatus.SUCCESS and ds_records.rdtype != DataType.DS.value:
        status = TestStatus.WARNING
        result = "NO DS records found in parent zone, zone is not signed"
        LOGGER.info(result)
    return TestStep(description=description, status=status, result=result), ds_records


def _check_ds_rrset(dsrrset: RRSet, chain_of_trust, qname) -> TestStep:
    """Check DS RRSET through RRSIG"""
    description = "Check if received DS records for {} are valid through RRSIG {}".format(qname, dsrrset.rrsig)

    try:
        if not dsrrset.is_valid(chain_of_trust):
            result = "DS records received for {} are not valid (RRSIG not verified)".format(qname)
            status = TestStatus.ERROR
        else:
            for rec in dsrrset.records:
                LOGGER.debug("Adding DS record %s to the chain of trust", rec)
                chain_of_trust.add_ds(rec)

            result = "DS records are valid"
            status = TestStatus.SUCCESS

    except DnsDebuggerException as err:
        status = TestStatus.ERROR
        result = err.message

    return TestStep(description=description, result=result, status=status)


def _get_dnskeys(qname: str, resolver: Resolver) -> Tuple[TestStep, RRSet]:
    """Get DNSKEY for a given qname"""
    description = 'Get DNSKEY for {}'.format(qname)

    try:
        dnskeys = dns_query(qname=qname, rdtype=DataType.DNSKEY, want_dnssec=True, resolver=resolver)
        status = TestStatus.SUCCESS
        result = str(dnskeys)

    except QueryNoResponseException:
        status = TestStatus.ERROR
        result = "Zone {} is not signed (there is no DNSKEY), but we have a parent DS record. " \
                 "Please remove DS record or sign the zone".format(qname)
        dnskeys = None

    return TestStep(description=description, result=result, status=status), dnskeys


def _validate_dnskeys_via_ds(dnskeyrrset, qname, chain_of_trust) -> List[TestStep]:
    """Validata dnskey via DS records"""
    testscases = []
    for dnskey in dnskeyrrset.records:
        if dnskey.is_ksk():
            description = 'Verify DNSKEY {} over DS DS for {}'.format(dnskey, qname)
            try:
                dnskey.is_validated_by_cot_ds(name=qname, cot=chain_of_trust)
                status = TestStatus.SUCCESS
                result = "DNSKEY validated"
            except DnsDebuggerException as err:
                status = TestStatus.ERROR
                result = err.message
            testscases.append(TestStep(description=description, status=status, result=result))

    return testscases


def _check_rrsig(qname, dnskeys, chain_of_trust) -> TestStep:
    """Check DNSKEYS through rrsig"""
    description = 'Check DNSKEY over RRSIG for {}'.format(qname)
    try:
        if not dnskeys.is_valid(cot=chain_of_trust):
            result = "DS records received for {} are not valid (RRSIG not verified)".format(qname)
            status = TestStatus.ERROR
        else:
            for dnskey in dnskeys.records:
                if chain_of_trust.get_dnskey(dnskey.key_tag()) is None:
                    chain_of_trust.add_dnskey(dnskey)

            status = TestStatus.SUCCESS
            result = "DNSKEY validated over RRSIG"
    except DnsDebuggerException as err:
        status = TestStatus.ERROR
        result = err.message

    return TestStep(description=description, status=status, result=result)
