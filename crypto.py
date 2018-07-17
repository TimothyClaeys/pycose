import base64
import binascii
import hashlib
import unittest
from hashlib import sha256
from os import urandom

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac

import ecdsa.curves
import ecdsa.keys

hashes_for_ecc = \
    {
        'ES256': hashlib.sha256,
        'ES384': hashlib.sha384,
        'ES512': hashlib.sha512
    }

hmacs = \
    {
        'HS256/64': hashes.SHA256,
        'HS256': hashes.SHA256,
        'HS384': hashes.SHA384,
        'HS512': hashes.SHA512
    }


ec_curves = \
    {
        'P-256': ecdsa.curves.NIST256p,
        'P-384' : ecdsa.curves.NIST384p
    }


def hmac_wrapper(key, to_be_maced, algorithm):
    """
    Wrapper function for the supported hmac in COSE
    :param key: key for computation of the hmac
    :param to_be_maced: byte string whose integrity need to be protected
    :param algorithm: chosen hmac, supports hmac with sha256, sha384 and sha512
    :return: returns the digest calculated with the chosen hmac function
    """
    hash_primitive = hmacs[algorithm]
    h = hmac.HMAC(key, hash_primitive(), backend=default_backend())
    h.update(to_be_maced)
    digest = h.finalize()

    if algorithm == 'HS256/64':
        # truncate the result to the first 64 bits
        digest = digest[:8]
    return digest


def hmac_verify_wrapper(key, tag, to_be_maced, algorithm):
    if algorithm != 'HS256/64':
        hash_primitive = hmacs[algorithm]
        h = hmac.HMAC(key, hash_primitive(), backend=default_backend())
        h.update(to_be_maced)
        h.verify(tag)
    elif algorithm == 'HS256/64':
        hash_primitive = hmacs[algorithm]
        h = hmac.HMAC(key, hash_primitive(), backend=default_backend())
        h.update(to_be_maced)
        if h.finalize()[:8] != tag:
            raise InvalidSignature("The authentication tags do not match")
    return True


def ec_sign_wrapper(key, to_be_signed, algorithm='ES256', curve='P-256'):
    if isinstance(key, str):
        signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    else:
        signer = key
    return signer.sign_deterministic(to_be_signed, hashfunc=hashes_for_ecc[algorithm])


def ec_verify_wrapper(key, to_be_signed, signature, algorithm='ES256', curve='P256'):
    if isinstance(key, str):
        signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    else:
        signer = key
    verifier = signer.get_verifying_key()
    return verifier.verify(signature, to_be_signed, hashfunc=hashes_for_ecc[algorithm])


def derive_priv_key(d, curve, hashfunc):
    d = base64urldecode(d)
    d = binascii.hexlify(d)
    d = int(d,16)
    return ecdsa.keys.SigningKey.from_secret_exponent(d, curve, hashfunc)


def derive_pub_key(x, y, curve, hashfunc):
    """
    Not sure if this actually works, examples provided on the github page are wrong (see issues)
    :param x: X coordinate of the elliptic curve
    :param y: Y coordinate of the elliptic curve
    :param curve: Which curve to use
    :param hashfunc: Which hash function used for hashing the data before signing
    :return: A public key
    """
    x = base64urldecode(x)
    x = binascii.hexlify(x)
    y = base64urldecode(y)
    y = binascii.hexlify(y)
    x = int(x,16)
    y = int(y, 16)
    point = ecdsa.ellipticcurve.Point(ecdsa.curves.NIST256p, x, y)
    return ecdsa.keys.VerifyingKey.from_public_point(point, ecdsa.curves.NIST256p, hashfunc=sha256)


def generate_crypto_keys(algorithm='ES256', curve='P-256'):
    if algorithm in ['ES256', 'ES384', 'ES512']:
        return ecdsa.SigningKey.generate(ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    if algorithm in ['HS256/64', 'HS256', 'HS384', 'HS512']:
        seed = get_randomness(64)
        key = hashes.Hash(hmacs[algorithm](), backend=default_backend())
        key.update(seed)
        return key.finalize()


def get_randomness(bytecount):
    return urandom(bytecount)


def base64urldecode(to_decode):
    to_decode = to_decode.replace('-', '+')
    to_decode = to_decode.replace('_', '/')

    if len(to_decode) % 4 == 0:
        return base64.b64decode(to_decode)
    if len(to_decode) % 4 == 2:
        to_decode = to_decode + "=="
        return base64.b64decode(to_decode)
    if len(to_decode) % 4 == 3:
        to_decode = to_decode + "="
        return base64.b64decode(to_decode)
