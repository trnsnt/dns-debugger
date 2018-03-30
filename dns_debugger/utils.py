"""Some utilities method"""
import dns.name


def split_qname(qname):
    """
    >>> split_qname("dnstests.fr.")
    ['.', 'fr.', 'dnstests.fr.']
    """
    splitted_qname = qname.split(".")[::-1]
    out = []
    current = ''
    for entry in splitted_qname:
        if entry == "":
            out.append(".")
        else:
            current = "%s.%s" % (entry, current)
            out.append(current)
    return out


def qname_to_wire(qname):
    """
    >>> wired = qname_to_wire("dnstests.fr.")[:-1]
    >>> wired == b'\x08dnstests\x02fr'
    True
    """
    return dns.name.Name(dns.name.from_text(qname)).to_wire()
