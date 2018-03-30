"""Utilities for dnsssec"""
from dns_debugger import LOGGER
from dns_debugger.dnssec.type import SignedRRSet
from dns_debugger.exceptions import DnsDebuggerException


def verify_signed_dnskey_rrset(rrset: SignedRRSet, cot, qname):
    """Verify a DNSKEY RRSET"""
    LOGGER.info("Checking if DNSKEY RRSET is valid")
    for dnskey in rrset.rrset.records:
        if dnskey.is_ksk():
            key_tag = dnskey.key_tag()
            cot_records = cot['DS'].get(key_tag)
            if not cot_records:
                LOGGER.debug("DNSKEY %s not verified by DS record", key_tag)
                continue
            for cot_record in cot_records:
                sig = dnskey.compute_sig(qname=qname, digest_type=cot_record.digest_type)
                LOGGER.debug("Computed signature for DNSKEY %s is %s", key_tag, sig)
                if sig.upper() != cot_record.digest_str.upper():
                    LOGGER.critical("Invalid DNSKEY record (computed=%s, parent=%s), exiting", sig,
                                    cot_record.digest_str.upper())
                    raise DnsDebuggerException("DNSKEY {} cannot be validated through parent DS record, signature are "
                                               "different {} != {}".format(key_tag, sig.upper(),
                                                                           cot_record.digest_str.upper()))
            LOGGER.info("DNSKEY %s validated through DS record ", key_tag)
            cot['DNSKEY'][key_tag] = dnskey
    LOGGER.info("Validation of DNSKEY with received RRSIG")
    if rrset.is_valid(cot):
        for dnskey in rrset.rrset.records:
            key_tag = dnskey.key_tag()
            cot['DNSKEY'][key_tag] = dnskey
    else:
        raise DnsDebuggerException(message="RRSET not validated through RRSIG\n{}".format(rrset.rrsig))
