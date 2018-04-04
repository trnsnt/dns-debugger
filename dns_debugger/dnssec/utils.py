"""Utilities for dnsssec"""
from dns_debugger import LOGGER
from dns_debugger.exceptions import DnsDebuggerException
from dns_debugger.models import ChainOfTrust
from dns_debugger.query import dns_query
from dns_debugger.records_models import RRSet, DataType


def get_and_check_parent_ds(qname, chain_of_trust):
    """
    :param qname:
    :param chain_of_trust:
    :return: True if DS record else False
    """
    if qname == ".":
        return True
    LOGGER.info("Get DS record for %s", qname)
    ds_records = dns_query(qname=qname, rdtype=DataType.DS, want_dnssec=True)
    if not ds_records.is_valid(chain_of_trust):
        message = "DS records received for {} are not valid (RRSIG not verified)".format(qname)
        raise DnsDebuggerException(message=message)

    if ds_records.rdtype != DataType.DS.value:
        LOGGER.info("NO DS records found in parent zone, zone is not signed")
        return False

    for rec in ds_records.records:
        LOGGER.debug("Adding DS record %s to the chain of trust", rec)
        chain_of_trust.add_ds(rec)
    return True


def verify_dnskey_rrset(rrset: RRSet, cot: ChainOfTrust, qname):
    """Verify a DNSKEY RRSET"""
    LOGGER.info("Checking if DNSKEY RRSET is valid")
    for dnskey in rrset.records:
        if dnskey.is_ksk():
            key_tag = dnskey.key_tag()
            cot_records = cot.get_ds(key_tag)
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
            cot.add_dnskey(dnskey)
    LOGGER.info("Validation of DNSKEY with received RRSIG")
    if rrset.is_valid(cot):
        for dnskey in rrset.records:
            cot.add_dnskey(dnskey)
    else:
        raise DnsDebuggerException(message="RRSET not validated through RRSIG\n{}".format(rrset.rrsig))
