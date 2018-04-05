"""All DNSSEC crypto related stuff"""
import binascii
import struct

from M2Crypto import EC, RSA, EVP
from M2Crypto.m2 import hex_to_bn, bn_to_mpi

from dns_debugger.exceptions import DnsDebuggerException


def _key_to_ec_pubkey(alg, key):
    """

    :param alg:
    :param key:
    :return:
    """
    if alg == 13:
        curve = EC.NID_X9_62_prime256v1
    elif alg == 14:
        curve = EC.NID_secp384r1
    else:
        raise DnsDebuggerException(message='Algorithm {} not supported'.format(alg))

    try:
        return EC.pub_key_from_params(curve, b'\x04' + key)
    except ValueError:
        raise DnsDebuggerException(message='Error when creating EC public key')


def is_ec_valid(key, msg, signature, alg):
    """Check if EC key verify signature"""
    pubkey = _key_to_ec_pubkey(alg, key)

    # if the key is invalid, then the signature is also invalid
    if pubkey is None:
        return False

    if alg in (13,):
        alg = 'sha256'
        sigsize = 64
    elif alg in (14,):
        alg = 'sha384'
        sigsize = 96
    else:
        raise DnsDebuggerException(message='EC hash algorithm unknown!')

    if sigsize != len(signature):
        return False

    offset = 0

    # get R
    new_offset = offset + sigsize // 2
    ec_r = bn_to_mpi(hex_to_bn(binascii.hexlify(signature[offset:new_offset])))
    offset = new_offset

    # get S
    new_offset = offset + sigsize // 2
    ec_s = bn_to_mpi(hex_to_bn(binascii.hexlify(signature[offset:new_offset])))

    message_digest = EVP.MessageDigest(alg)
    message_digest.update(msg)
    digest = message_digest.final()

    return pubkey.verify_dsa(digest, ec_r, ec_s) == 1


def _key_to_rsa_pubkey(key):
    try:
        # get the exponent length
        e_len, = struct.unpack(b'B', key[0:1])
    except IndexError:
        return None
    offset = 1
    if e_len == 0:
        e_len, = struct.unpack(b'!H', key[1:3])
        offset = 3

    # get the exponent
    rsa_e = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:offset + e_len])))
    offset += e_len

    # get the modulus
    rsa_n = bn_to_mpi(hex_to_bn(binascii.hexlify(key[offset:])))

    # create the RSA public key
    rsa = RSA.new_pub_key((rsa_e, rsa_n))
    pubkey = EVP.PKey()
    pubkey.assign_rsa(rsa)
    return pubkey


def is_rsa_valid(key, msg, signature, alg):
    """Check if RSA key verify signature"""
    pubkey = _key_to_rsa_pubkey(key)

    if alg in (1,):
        message_digest = 'md5'
    elif alg in (5, 7):
        message_digest = 'sha1'
    elif alg in (8,):
        message_digest = 'sha256'
    elif alg in (10,):
        message_digest = 'sha512'
    else:
        raise DnsDebuggerException(message='RSA Algorithm unknown.')

    pubkey.reset_context(md=message_digest)
    pubkey.verify_init()
    pubkey.verify_update(msg)
    return pubkey.verify_final(signature) == 1
