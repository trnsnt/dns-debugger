"""
Class related to record
"""
import base64
import binascii
import hashlib
import struct
import typing
from datetime import datetime
from enum import Enum

from dns_debugger import LOGGER
from dns_debugger.dnssec.crypto import is_rsa_valid, is_ec_valid
from dns_debugger.exceptions import DnsDebuggerException
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

    def __repr__(self):
        return str(self)


class A(Record):  # pylint: disable=invalid-name, too-few-public-methods
    """A record"""
    address: str

    def __init__(self, rdata, address: str):
        super(A, self).__init__(rdata=rdata)
        self.address = address

    def __str__(self):
        return '{address}'.format(address=self.address)


class AAAA(Record):  # pylint: disable=too-few-public-methods
    """AAAA record"""
    address: str

    def __init__(self, rdata, address: str):
        super(AAAA, self).__init__(rdata=rdata)
        self.address = address

    def __str__(self):
        return '{address}'.format(address=self.address)


class TXT(Record):  # pylint: disable=too-few-public-methods
    """TXT record"""
    value: str

    def __init__(self, rdata, value: str):
        super(TXT, self).__init__(rdata=rdata)
        self.value = value

    def __str__(self):
        return '{value}'.format(value=self.value)


class NS(Record):  # pylint: disable=too-few-public-methods
    """NS record"""
    target: str

    def __init__(self, rdata, target: str):
        super(NS, self).__init__(rdata=rdata)
        self.target = target

    def __str__(self):
        return '{target}'.format(target=self.target)


class MX(Record):  # pylint: disable=too-few-public-methods
    """MX record"""
    target: str
    preference: int

    def __init__(self, rdata, target: str, preference: int):
        super(MX, self).__init__(rdata=rdata)
        self.target = target
        self.preference = preference

    def __str__(self):
        return '{preference} {target}'.format(preference=self.preference, target=self.target)


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
        return '{server} {email} {serial} ' \
               '{refresh} {ttl} {expire} {minimum}'.format(ttl=self.ttl, server=self.server, email=self.email,
                                                           serial=self.serial, refresh=self.refresh,
                                                           expire=self.expire, minimum=self.minimum)


class RRSig(Record):
    """RRSIG record"""
    algorithm: int
    expiration: datetime
    inception: datetime
    key_tag: int
    signature: str
    signer: str
    type_covered: int
    original_ttl: int
    labels: int
    signer_wire: bytes

    def __init__(self, rdata, algorithm: int, expiration: int, inception: int, key_tag: int, signature: bytes,
                 signer: str,
                 type_covered: int, original_ttl: int, labels: int):
        super(RRSig, self).__init__(rdata=rdata)
        self.algorithm = algorithm
        self.expiration = expiration
        self.inception = inception
        self.key_tag = key_tag
        self.signature = signature
        self.signer = signer
        self.type_covered = type_covered
        self.original_ttl = original_ttl
        self.labels = labels

    @property
    def signature_str(self) -> str:
        """Signature to str"""
        return str(base64.b64encode(self.signature), 'ascii')

    def canonicalized_wire(self):
        """To wire"""
        rdata_wire = struct.pack(b'!HBBIIIH', self.type_covered,
                                 self.algorithm, self.labels,
                                 self.original_ttl, self.expiration,
                                 self.inception, self.key_tag)
        signer_wire = qname_to_wire(self.signer)
        return rdata_wire + signer_wire

    def __str__(self):
        return '{type} {algo} {label} {ttl} {expiration} {inception} ' \
               '{key_tag} {signer} {signature}'.format(type=self.type_covered, algo=self.algorithm,
                                                       expiration=self.expiration, inception=self.inception,
                                                       key_tag=self.key_tag, signer=self.signer,
                                                       signature=self.signature_str, label=self.labels,
                                                       ttl=self.original_ttl)


class PTR(Record):  # pylint: disable=invalid-name, too-few-public-methods
    """A record"""
    target: str

    def __init__(self, rdata, target: str):
        super(PTR, self).__init__(rdata=rdata)
        self.target = target

    def __str__(self):
        return '{target}'.format(target=self.target)


class DS(Record):
    """DS record"""
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes

    def __init__(self, rdata, key_tag: int, algorithm: int, digest_type: int, digest: bytes):
        super(DS, self).__init__(rdata=rdata)
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest

    @property
    def digest_str(self) -> str:
        """Digest to str"""
        return str(binascii.hexlify(self.digest).upper(), 'ascii')

    def __str__(self):
        return '{key_tag} {algo} {digest_type} {digest}'.format(key_tag=self.key_tag, algo=self.algorithm,
                                                                digest_type=self.digest_type,
                                                                digest=self.digest_str)


class DnsKey(Record):
    """DNSKEY record"""
    flags: int
    protocol: int
    algo: int
    public_key: bytes

    def __init__(self, rdata, flags: int, protocol: int, algo: int, public_key: bytes):
        super(DnsKey, self).__init__(rdata=rdata)
        self.flags = flags
        self.protocol = protocol
        self.algo = algo
        self.public_key = public_key

    @property
    def pk_str(self) -> str:
        """Digest to str"""
        return str(base64.b64encode(self.public_key), 'ascii')

    def is_ksk(self):
        """Is DNSKEY is a key signing key"""
        return self.flags == 257

    def is_zsk(self):
        """Is DNSKEY is a zone signing key"""
        return self.flags == 256

    def key_tag(self):
        """Get keytag"""
        stru = struct.pack('!HBB', int(self.flags), int(self.protocol), int(self.algo))
        stru += self.public_key

        cnt = 0
        for idx in range(len(stru)):
            element = struct.unpack('B', stru[idx:idx + 1])[0]
            if (idx % 2) == 0:
                cnt += element << 8
            else:
                cnt += element

        return ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF

    def compute_sig(self, qname, digest_type):
        """Compute signature"""
        signature = bytes()

        if qname == ".":
            qname = qname[:-1]
        for i in qname.split('.'):
            signature += struct.pack('B', len(i)) + i.encode()

        signature += struct.pack('!HBB', int(self.flags), int(self.protocol), int(self.algo))
        signature += self.public_key

        if digest_type == 2:
            return hashlib.sha256(signature).hexdigest().upper()
        elif digest_type == 1:
            return hashlib.sha1(signature).hexdigest().upper()
        raise DnsDebuggerException("Unknown digest type {}".format(digest_type))

    def __str__(self):
        return '{flags} {protocol} {algo} {pk}... ; {key_tag}'.format(flags=self.flags, protocol=self.protocol,
                                                                      algo=self.algo,
                                                                      pk=self.pk_str[:25], key_tag=self.key_tag())


class RRSet(Record):
    """RRSET is a list of records of the same type"""

    records: typing.List[Record]
    name: str
    rdtype: int
    rdclass: int
    ttl: int
    rrsig: typing.List[RRSig]

    def __init__(self, rdata, records: typing.List[Record], name: str, rdtype: int, rdclass: int, ttl: int,
                 rrsig=None):
        super(RRSet, self).__init__(rdata=rdata)
        self.records = records
        self.name = name
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.ttl = ttl
        self.rrsig = rrsig or []

    def is_signed(self):
        return bool(self.rrsig)

    def canonicalized_wire_rrset(self, original_ttl):
        """return wire"""
        wired = b''
        for record in sorted(self.records):
            wired += record.to_wire(name=self.name, dtype=self.rdtype, dclass=self.rdclass, ttl=original_ttl)
        return wired

    def is_valid(self, cot):
        """Check if RRSet is valid through RRSig"""
        LOGGER.info("Checking if RRSET is validated by RRSIG %s", self)
        for rrsig in self.rrsig:
            signing_key = cot.get_dnskey(rrsig.key_tag)
            if signing_key is None:
                # We have a DNSKEY, look in it
                if self.rdtype == DataType.DNSKEY.value:
                    for record in self.records:
                        if record.key_tag() == rrsig.key_tag:
                            signing_key = record
                            break
                if signing_key is None:
                    LOGGER.warning("RRSIG key_tag %s is not in the chain of trust", rrsig.key_tag)
                    raise DnsDebuggerException("RRSIG key_tag {} is not in the chain of trust".format(rrsig.key_tag))
            if rrsig.algorithm in (5, 7, 8, 10):
                return is_rsa_valid(key=signing_key.public_key, msg=self.compute_msg(rrsig=rrsig),
                                    signature=rrsig.signature,
                                    alg=signing_key.algo)
            elif rrsig.algorithm in (13, 14):
                return is_ec_valid(signing_key.public_key, msg=self.compute_msg(rrsig=rrsig),
                                   signature=rrsig.signature,
                                   alg=rrsig.algorithm)
            raise DnsDebuggerException("RRSIG algorithm {} not yet supported".format(rrsig.algorithm))

    def compute_msg(self, rrsig):
        """Compute msg"""
        return rrsig.canonicalized_wire() + self.canonicalized_wire_rrset(original_ttl=rrsig.original_ttl)

    def __str__(self):
        values = ", ".join(map(lambda x: '{}'.format(x), self.records))
        rrset = '[RRSET-{type}][TTL:{ttl}][{values}]'.format(values=values, type=DataType(self.rdtype).name,
                                                             ttl=self.ttl)
        if self.rrsig:
            return '{rrset}\n  [RRSIG][{rrsig}]'.format(rrset=rrset, rrsig=self.rrsig)
        return rrset
