"""All methods related to DNS query"""
import random
import typing
from typing import Optional, Dict

import dns
from dns import resolver as dnsresolver
from dns.rcode import NOERROR, _by_value

from dns_debugger import LOGGER
from dns_debugger.exceptions import QueryTimeException, QueryErrException, DnsDebuggerException, \
    QueryNoResponseException
from dns_debugger.records_models import RRSet, DataType, A, TXT, NS, Soa, AAAA, MX, DnsKey, RRSig, DS, PTR, Record

DEFAULT_TIMEOUT = 10

MODELS_MAP: Dict[int, Record] = {
    DataType.A.value: A,
    DataType.TXT.value: TXT,
    DataType.NS.value: NS,
    DataType.SOA.value: Soa,
    DataType.AAAA.value: AAAA,
    DataType.MX.value: MX,
    DataType.DNSKEY.value: DnsKey,
    DataType.RRSIG.value: RRSig,
    DataType.DS.value: DS,
    DataType.PTR.value: PTR
}


class Resolver(typing.NamedTuple("Resolver", [("ip_addr", str), ("qname", str)])):
    """Resolver"""

    def __new__(cls, ip_addr: Optional[str] = None, qname: Optional[str] = None):

        if ip_addr is None and qname is None:
            ip_addr = dnsresolver.Resolver().nameservers[0]
            qname = "default.resolver"

        elif qname and ip_addr is None:
            ips = dns_query(qname=qname, rdtype=DataType.A)
            ip_addr = random.choice(ips.records).address

        elif ip_addr and qname is None:
            arpa_qname = dns.reversename.from_address(ip_addr)
            qname = dns_query(qname=arpa_qname, rdtype=DataType.PTR).records[0].target

        return super(Resolver, cls).__new__(cls, ip_addr, qname)

    def __str__(self):
        return '[{} | {}]'.format(self.qname, self.ip_addr)


def dns_query(qname: str, rdtype: DataType, want_dnssec: bool = False, resolver: Optional['Resolver'] = None) -> RRSet:
    """Make a DNS query"""
    if resolver is None:
        resolver = Resolver()

    LOGGER.debug("Querying %s for type %s, origin %s", qname, rdtype.name, resolver)

    response = run_query(resolver.ip_addr, qname, rdtype, want_dnssec)

    answer = response.answer or response.authority
    if not answer:
        LOGGER.critical("No answer received for type %s, origin %s", rdtype.name, resolver)
        raise QueryErrException(message="No answer received")

    if want_dnssec and len(answer) < 2:
        raise QueryNoResponseException(message="DNSSEC not supported")

    mapped_answers = map_answers(answer, want_dnssec)
    LOGGER.debug("Response is %s", mapped_answers)
    return mapped_answers


def map_answers(answer, want_dnssec):
    """
    Map answers from dnspython to own object
    :param answer: Answer received from dnspython
    :param want_dnssec: DNSSEC wanted or not, will set rrsig if wanted
    :return:
    """
    received_rrset = answer[0]
    records = list(map(_map_pythondns_record, received_rrset.items))
    rrset = RRSet(rdata=received_rrset, name=received_rrset.name.to_text(), records=records,
                  rdtype=received_rrset.rdtype, rdclass=received_rrset.rdclass, ttl=received_rrset.ttl)
    if want_dnssec:
        rrset.rrsig = [_map_pythondns_record(r) for r in answer[1]]
    return rrset


def run_query(resolver_ip: str, qname: str, rdtype: DataType, want_dnssec: bool):
    """
    Make a DNS query
    :param resolver_ip: IP of wanted resolver
    :param qname: qname to target
    :param rdtype: type to record to target
    :param want_dnssec: Want DNSSEC or not
    :return:
    """
    message = dns.message.make_query(qname, rdtype.value, use_edns=0, payload=4096, want_dnssec=want_dnssec)
    try:
        response = dns.query.udp(message, resolver_ip, timeout=DEFAULT_TIMEOUT)
    except dns.exception.Timeout:
        raise QueryTimeException(message="Timeout during dns query "
                                         "(origin={}, dest={}, type={})".format(resolver_ip, qname, rdtype.name))
    if response.rcode() != NOERROR:
        raise QueryErrException(message="Error during DNS query, status is {}".format(_by_value.get(response.rcode())))
    return response


def _map_pythondns_record(record):
    """Get a record form pythondns and map it to our format"""
    record_cls = MODELS_MAP.get(record.rdtype)
    if record_cls is None:
        raise DnsDebuggerException("Unknown record type %s" % record.rdtype)
    return record_cls.create_from_rdata(rdata=record)
