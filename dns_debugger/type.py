"""
Class related to record
"""
import struct
import typing
from enum import Enum

from dns_debugger.utils import qname_to_wire


class DataType(Enum):
    """Enum for data type"""
    NONE = 0
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    HIP = 55
    CDS = 59
    CDNSKEY = 60
    CSYNC = 62
    SPF = 99
    UNSPEC = 103
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255
    URI = 256
    CAA = 257
    AVC = 258
    TA = 32768
    DLV = 32769


class Record:
    """DNS record"""
    _rdata = None  # _rdata is dnspython object. We be removed when all dnspython methods will be implemented

    # type, class, name and ttl are stored in the parent rrset

    def __init__(self, rdata):
        self._rdata = rdata

    def to_wire(self, name, dtype, dclass, ttl):
        """Wire a record"""
        name_wire = qname_to_wire(name)
        rdata_wire = self._rdata.to_digestable()
        rdata_len = len(rdata_wire)

        stuff = struct.pack("!HHIH", dtype, dclass, ttl, rdata_len)
        return name_wire + stuff + rdata_wire

    def __eq__(self, other):
        """Used to order record list"""
        return self._rdata.to_digestable() == other._rdata.to_digestable()

    def __lt__(self, other):
        """Used to order record list"""
        return self._rdata.to_digestable() < other._rdata.to_digestable()


class A(Record):  # pylint: disable=invalid-name, too-few-public-methods
    """A record"""
    address: str

    def __init__(self, rdata, address: str):
        super(A, self).__init__(rdata=rdata)
        self.address = address

    def __str__(self):
        return '[A] [{address}]'.format(address=self.address)


class AAAA(Record):  # pylint: disable=too-few-public-methods
    """AAAA record"""
    address: str

    def __init__(self, rdata, address: str):
        super(AAAA, self).__init__(rdata=rdata)
        self.address = address

    def __str__(self):
        return '[AAAA] [{address}]'.format(address=self.address)


class TXT(Record):  # pylint: disable=too-few-public-methods
    """TXT record"""
    value: str

    def __init__(self, rdata, value: str):
        super(TXT, self).__init__(rdata=rdata)
        self.value = value

    def __str__(self):
        return '[TXT] [{value}]'.format(value=self.value)


class NS(Record):  # pylint: disable=too-few-public-methods
    """NS record"""
    target: str

    def __init__(self, rdata, target: str):
        super(NS, self).__init__(rdata=rdata)
        self.target = target

    def __str__(self):
        return '[NS] [{target}]'.format(target=self.target)


class MX(Record):  # pylint: disable=too-few-public-methods
    """MX record"""
    target: str
    preference: int

    def __init__(self, rdata, target: str, preference: int):
        super(MX, self).__init__(rdata=rdata)
        self.target = target
        self.preference = preference

    def __str__(self):
        return '[MX] [{preference} {target}]'.format(preference=self.preference, target=self.target)


class Soa(Record):  # pylint: disable=too-few-public-methods
    """SOA record"""
    expire: int
    minimum: int
    refresh: int
    ttl: int
    serial: int
    server: str
    email: str

    def __init__(self, rdata, ttl: int, server: str, email: str, refresh: int, expire: int, minimum: int, serial: int):
        super(Soa, self).__init__(rdata=rdata)
        self.expire = expire
        self.minimum = minimum
        self.refresh = refresh
        self.ttl = ttl
        self.serial = serial
        self.server = server
        self.email = email

    def __str__(self):
        return '[SOA] {server} {email} {serial} ' \
               '{refresh} {ttl} {expire} {minimum}'.format(ttl=self.ttl, server=self.server, email=self.email,
                                                           serial=self.serial, refresh=self.refresh,
                                                           expire=self.expire, minimum=self.minimum)


class RRSet(Record):
    """RRSET is a list of records of the same type"""

    records: typing.List[Record]
    name: str
    rdtype: int
    rdclass: int
    ttl: int

    def __init__(self, rdata, records: typing.List[Record], name: str, rdtype: int, rdclass: int, ttl: int):
        super(RRSet, self).__init__(rdata=rdata)
        self.records = records
        self.name = name
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.ttl = ttl

    def canonicalized_wire(self, ttl):
        """return wire"""
        wired = b''
        for record in sorted(self.records):
            wired += record.to_wire(name=self.name, dtype=self.rdtype, dclass=self.rdclass, ttl=ttl)
        return wired

    def __str__(self):
        return '[RRSET] {values}'.format(values=", ".join(map(lambda x: '[{}]'.format(x), self.records)))
