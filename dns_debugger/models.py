"""Models for dns_debugger"""
import binascii
from typing import Dict, Optional

import collections

from dns_debugger import LOGGER
from dns_debugger.records_models import DS, DnsKey


class ChainOfTrust:
    """DNSSEC chain of trust"""
    ds_records: Dict
    dnskeys: Dict

    def __init__(self):
        self.ds_records = collections.defaultdict(list)
        self.dnskeys = dict()

        self.add_ds(DS(rdata=None, key_tag=19036, algorithm=8, digest_type=2,
                       digest=binascii.unhexlify("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")))

        self.add_ds(DS(rdata=None, key_tag=20326, algorithm=8, digest_type=2,
                       digest=binascii.unhexlify("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")))

    def add_ds(self, record: DS):
        """Add DS record to chain of trust"""
        LOGGER.info("Adding DS record to chain of trust %s", record)
        self.ds_records[record.key_tag].append(record)

    def add_dnskey(self, record: DnsKey):
        """Add DNSKEY record to chain of trust"""
        LOGGER.info("Adding DNSKEY record to chain of trust %s", record)
        self.dnskeys[record.key_tag()] = record

    def get_dnskey(self, keytag: str) -> Optional[DnsKey]:
        """Get dnskey from keytag"""
        return self.dnskeys.get(keytag)

    def get_ds(self, keytag: str) -> Optional[DS]:
        """Get ds from keytag"""
        return self.ds_records.get(keytag)
