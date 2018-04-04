import binascii
import random
from collections import defaultdict
from typing import Dict

import dns
from dns import resolver

from dns_debugger import LOGGER
from dns_debugger.records_models import DataType, DS, DnsKey


class Resolver:
    ip_addr: str
    qname: str

    def __init__(self, ip_addr=None, qname=None):
        from dns_debugger.query import dns_query
        if ip_addr is None and qname is None:
            self.ip_addr = resolver.Resolver().nameservers[0]
            self.qname = "default.resolver"

        elif qname and not ip_addr:

            ips = dns_query(qname=qname, rdtype=DataType.A)
            self.ip_addr = random.choice(ips.records).address
            self.qname = qname

        elif ip_addr and not qname:
            arpa_qname = dns.reversename.from_address(ip_addr)
            self.qname = dns_query(qname=arpa_qname, rdtype=DataType.PTR).records[0].target
            self.ip_addr = ip_addr

        else:
            self.ip_addr = ip_addr
            self.qname = qname

    def __str__(self):
        return '[{} | {}]'.format(self.qname, self.ip_addr)


class ChainOfTrust:
    ds_records: Dict
    dnskeys: Dict

    def __init__(self):
        self.ds_records = defaultdict(list)
        self.dnskeys = dict()

        self.add_ds(DS(rdata=None, key_tag=19036, algorithm=8, digest_type=2,
                       digest=binascii.unhexlify("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")))

        self.add_ds(DS(rdata=None, key_tag=20326, algorithm=8, digest_type=2,
                       digest=binascii.unhexlify("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")))

    def add_ds(self, record: DS):
        LOGGER.info("Adding DS record to chain of trust %s", record)
        self.ds_records[record.key_tag].append(record)

    def add_dnskey(self, record: DnsKey):
        LOGGER.info("Adding DNSKEY record to chain of trust %s", record)
        self.dnskeys[record.key_tag()] = record

    def get_dnskey(self, keytag: str):
        return self.dnskeys.get(keytag)

    def get_ds(self, keytag: str):
        return self.ds_records.get(keytag)
