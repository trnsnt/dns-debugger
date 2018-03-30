"""Class related to DNSSEC"""
import base64
import binascii
import hashlib
import struct
from datetime import datetime

from dns_debugger import LOGGER
from dns_debugger.dnssec.crypto import is_rsa_valid, is_ec_valid
from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.type import RRSet, Record
from dns_debugger.utils import qname_to_wire


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

    def __str__(self):
        return '[RRSIG] [{type} {algo} {label} {ttl} {expiration} {inception} ' \
               '{key_tag} {signer} {signature}'.format(type=self.type_covered, algo=self.algorithm,
                                                       expiration=self.expiration, inception=self.inception,
                                                       key_tag=self.key_tag, signer=self.signer,
                                                       signature=self.signature_str, label=self.labels,
                                                       ttl=self.original_ttl)


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
        return '[DS] [{key_tag} {algo} {digest_type} {digest}]'.format(key_tag=self.key_tag, algo=self.algorithm,
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


class SignedRRSet:
    """Signed RRSET, it's in fact RRSet and RRSig"""
    rrset: RRSet
    rrsig: RRSig

    def __init__(self, rrset=None, rrsig=None):
        self.rrset = rrset if rrset is not None else []
        self.rrsig = rrsig

    def is_valid(self, cot):
        """Check if RRSet is valid through RRSig"""
        LOGGER.info("Checking is RRSET is validated by RRSIG")
        signing_key = cot['DNSKEY'].get(self.rrsig.key_tag)
        if signing_key is None:
            LOGGER.warning("RRSIG key_tag %s is not in the chain of trust", self.rrsig.key_tag)
            raise DnsDebuggerException("RRSIG key_tag {} is not in the chain of trust".format(self.rrsig.key_tag))
        if self.rrsig.algorithm in (5, 7, 8, 10):
            return is_rsa_valid(key=signing_key.public_key, msg=self.compute_msg(), signature=self.rrsig.signature,
                                alg=signing_key.algo)
        elif self.rrsig.algorithm in (13, 14):
            return is_ec_valid(signing_key.public_key, msg=self.compute_msg(), signature=self.rrsig.signature,
                               alg=self.rrsig.algorithm)
        raise DnsDebuggerException("RRSIG algorithm {} not yet supported".format(self.rrsig.algorithm))

    def compute_msg(self):
        """Compute msg"""
        return self.canonicalized_wire() + self.rrset.canonicalized_wire(ttl=self.rrsig.original_ttl)

    def canonicalized_wire(self):
        """To wire"""
        rdata_wire = struct.pack(b'!HBBIIIH', self.rrsig.type_covered,
                                 self.rrsig.algorithm, self.rrsig.labels,
                                 self.rrsig.original_ttl, self.rrsig.expiration,
                                 self.rrsig.inception, self.rrsig.key_tag)
        signer_wire = qname_to_wire(self.rrsig.signer)
        return rdata_wire + signer_wire
