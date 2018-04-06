"""Just make simple basic query"""
from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.executors.testsuite import TestCase, TestStep, TestStatus

from dns_debugger.query import dns_query, Resolver
from dns_debugger.records_models import DataType

RESOLVERS = [Resolver(), Resolver(ip_addr='8.8.8.8'), Resolver(ip_addr='9.9.9.9'), Resolver(ip_addr='1.1.1.1')]


def run_tests(qname: str):
    """Run the test"""
    suites = []
    for datatype in [DataType.SOA, DataType.NS, DataType.A, DataType.AAAA, DataType.MX, DataType.TXT]:
        testcase = TestCase(description="Get {dtype} records for {qname}".format(dtype=datatype.name, qname=qname))
        for resolver in RESOLVERS:
            for is_tcp in [False]:
                testcase.add_step(_query(qname=qname, dtype=datatype, resolver=resolver, is_tcp=is_tcp))
        suites.append(testcase)
    return suites


def _query(qname: str, dtype: DataType, resolver, is_tcp) -> TestStep:
    """Make the dns query"""
    if resolver is None:
        resolver_name = "default resolver"
    else:
        resolver_name = resolver
    description = "{protocol} with resolver: {res}".format(protocol='TCP' if is_tcp else "UDP", res=resolver_name)
    try:
        records = dns_query(qname=qname, rdtype=dtype, resolver=resolver, is_tcp=is_tcp)
        return TestStep(description=description, result=str(records), status=TestStatus.SUCCESS)
    except DnsDebuggerException as err:
        return TestStep(description=description, result=err.message, status=TestStatus.ERROR)
