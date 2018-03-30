"""Test executor to check the zone"""

from dns_debugger.executors.testsuite import TestSuite


def run_tests(qname):
    """Running tests"""
    if not qname.endswith("."):
        qname += "."

    from dns_debugger.executors import simple_query, recursive_query, dnssec_validation
    testsuite = TestSuite()
    testsuite.add_testcases(simple_query.run_tests(qname=qname))
    testsuite.add_testcases(recursive_query.run_tests(qname=qname))
    testsuite.add_testcases(dnssec_validation.run_tests(qname=qname))
    return testsuite
