"""All methods related to DNS query"""
from typing import Union

import dns
from dns import resolver
from dns.rcode import NOERROR, _by_value

from dns_debugger import LOGGER
from dns_debugger.dnssec.type import SignedRRSet, DS, DnsKey, RRSig
from dns_debugger.exceptions import QueryTimeException, QueryErrException, DnsDebuggerException, \
    QueryNoResponseException
from dns_debugger.type import RRSet, DataType, A, TXT, NS, Soa, AAAA, MX

DEFAULT_TIMEOUT = 1


def dns_query(qname: str, rdtype: DataType, want_dnssec=False, origin: str = None) -> Union[RRSet, SignedRRSet]:
    """Make a DNS query"""
    LOGGER.debug("Querying %s for type %s, origin %s", qname, rdtype.name, origin)
    if origin is None:
        origin = resolver.Resolver().nameservers[0]

    message = dns.message.make_query(qname, rdtype.value, use_edns=0, payload=4096, want_dnssec=want_dnssec)
    try:
        response = dns.query.udp(message, origin, timeout=DEFAULT_TIMEOUT)
    except dns.exception.Timeout:
        raise QueryTimeException(message="Timeout during dns query (origin={}, dest={}, type={})".format(origin,
                                                                                                         qname,
                                                                                                         rdtype.name))
    if response.rcode() != NOERROR:
        raise QueryErrException(message="Error during DNS query, status is {}".format(_by_value.get(response.rcode())))

    if response.answer:
        answers = response.answer
    elif response.authority:
        answers = response.authority
    else:
        raise QueryErrException(message="No answer received")

    if want_dnssec and len(response.answer) < 2:
        raise QueryNoResponseException(message="DNSSEC not supported")

    items = [item for item in answers[0].items if item.rdtype == rdtype.value]
    if not items:
        records = []
    else:
        records = list(map(lambda r: _map_pythondns_record(r), items))
    rrset = RRSet(rdata=answers[0], name=qname, records=records, rdtype=answers[0].rdtype, rdclass=answers[0].rdclass,
                  ttl=answers[0].ttl)
    if want_dnssec:
        return SignedRRSet(rrset=rrset, rrsig=_map_pythondns_record(answers[1][0]))
    return rrset


def _map_pythondns_record(record):
    """Get a record form pythondns and map it to our format"""
    if record.rdtype == DataType.A.value:
        return A(rdata=record, address=record.address)
    elif record.rdtype == DataType.TXT.value:
        return TXT(rdata=record, value="".join(map(str, record.strings)))
    elif record.rdtype == DataType.NS.value:
        return NS(rdata=record, target=record.target.to_text())
    elif record.rdtype == DataType.SOA.value:
        return Soa(rdata=record, ttl=record.retry, server=record.mname.to_text(), email=record.rname.to_text(),
                   refresh=record.refresh, expire=record.expire, minimum=record.minimum, serial=record.serial)
    elif record.rdtype == DataType.AAAA.value:
        return AAAA(rdata=record, address=record.address)
    elif record.rdtype == DataType.MX.value:
        return MX(rdata=record, target=record.exchange.to_text(), preference=record.preference)
    elif record.rdtype == DataType.DNSKEY.value:
        return DnsKey(rdata=record, flags=record.flags, protocol=record.protocol, algo=record.algorithm,
                      public_key=record.key)
    elif record.rdtype == DataType.RRSIG.value:
        return RRSig(rdata=record, algorithm=record.algorithm, expiration=record.expiration,
                     inception=record.inception,
                     key_tag=record.key_tag, signature=record.signature, signer=record.signer.to_text(),
                     type_covered=record.type_covered, original_ttl=record.original_ttl, labels=record.labels)
    elif record.rdtype == DataType.DS.value:
        return DS(rdata=record, key_tag=record.key_tag, algorithm=record.algorithm, digest_type=record.digest_type,
                  digest=record.digest)

    raise DnsDebuggerException("Unknown record type %s" % record.rdtype)
