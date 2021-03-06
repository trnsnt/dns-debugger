"""Just make simple basic query"""
from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.executors.testsuite import TestCase

from dns_debugger.query import dns_query, Resolver
from dns_debugger.records_models import DataType

RESOLVERS = [Resolver(), Resolver(ip_addr='8.8.8.8'), Resolver(ip_addr='9.9.9.9'), Resolver(ip_addr='1.1.1.1')]


def run_tests(qname: str):
    """Run the test"""
    suites = []
    for datatype in [DataType.SOA, DataType.NS, DataType.A, DataType.AAAA, DataType.MX, DataType.TXT]:
        for resolver in RESOLVERS:
            suites.append(_query(qname=qname, dtype=datatype, resolver=resolver))
    return suites


def _query(qname: str, dtype: DataType, resolver) -> TestCase:
    """Make the dns query"""
    if resolver is None:
        resolver_name = "default resolver"
    else:
        resolver_name = resolver
    description = "Get {dtype} records for {qname} from {res}".format(dtype=dtype.name, qname=qname, res=resolver_name)
    try:
        records = dns_query(qname=qname, rdtype=dtype, resolver=resolver)
        return TestCase(description=description, result=str(records), success=True)
    except DnsDebuggerException as err:
        return TestCase(description=description, result=err.message, success=False)
