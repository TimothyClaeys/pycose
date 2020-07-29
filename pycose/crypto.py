import hashlib
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import algorithms, aead
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from ecdsa import curves
from ecdsa import keys

from pycose.attributes import CoseAlgorithm
from pycose.exceptions import *

aes_key_wraps = {CoseAlgorithm.A128KW, CoseAlgorithm.A192KW, CoseAlgorithm.A256KW}

hashes_for_ecc = \
    {
        'ES256': hashlib.sha256,
        'ES384': hashlib.sha384,
        'ES512': hashlib.sha512,
    }

hmacs = \
    {
        'HMAC 256/64': hashes.SHA256,
        'HMAC 256/256': hashes.SHA256,
        'HMAC 384/384': hashes.SHA384,
        'HMAC 512/512': hashes.SHA512,
    }

cmacs = \
    {
        'AES-MAC 256/64': algorithms.AES,
        'AES-MAC-256/128': algorithms.AES,
        'AES-MAC 128/64': algorithms.AES,
        'AES-MAC 128/128': algorithms.AES,
    }

aeads = \
    {
        CoseAlgorithm.A128GCM: (aead.AESGCM, 16),
        CoseAlgorithm.A192GCM: (aead.AESGCM, 16),
        CoseAlgorithm.A256GCM: (aead.AESGCM, 16),
        CoseAlgorithm.AES_CCM_16_64_128: (aead.AESCCM, 8),
        CoseAlgorithm.AES_CCM_16_64_256: (aead.AESCCM, 8),
        CoseAlgorithm.AES_CCM_64_64_128: (aead.AESCCM, 8),
        CoseAlgorithm.AES_CCM_64_64_256: (aead.AESCCM, 8),
        CoseAlgorithm.AES_CCM_16_128_128: (aead.AESCCM, 16),
        CoseAlgorithm.AES_CCM_16_128_256: (aead.AESCCM, 16),
        CoseAlgorithm.AES_CCM_64_128_256: (aead.AESCCM, 16),
        CoseAlgorithm.AES_CCM_64_128_128: (aead.AESCCM, 16),
    }

ec_curves = \
    {
        'P-256': curves.NIST256p,
        'P-384': curves.NIST384p,
    }


def aead_encrypt(key, aad, plaintext, algorithm, nonce):
    try:
        primitive, tag_length = aeads[algorithm]
        if tag_length != 16:
            aead_cipher = primitive(key, tag_length=tag_length)
        else:
            aead_cipher = primitive(key)
        ciphertext = aead_cipher.encrypt(nonce, plaintext, aad)
    except KeyError as err:
        raise CoseUnsupportedEnc("This cipher is not supported by the COSE specification: {}".format(err))

    return ciphertext


def aead_decrypt(key, aad, ciphertext, algorithm, nonce):
    try:
        primitive = aeads[algorithm]
        aesgcm = primitive(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except KeyError as err:
        raise CoseUnsupportedEnc("This cipher is not supported by the COSE specification: {}".format(err))

    return plaintext


def key_wrap(alg, kek, plaintext_key):
    if alg in aes_key_wraps:
        return aes_key_wrap(kek, plaintext_key, default_backend())
    elif alg == CoseAlgorithm.DIRECT:
        return b''


def calc_tag_wrapper(key, to_be_maced, algorithm):
    """
    Wrapper function for the supported hmac in COSE
    :param key: key for computation of the hmac
    :param to_be_maced: byte string whose integrity need to be protected
    :param algorithm: chosen hmac, supports hmac with sha256, sha384 and sha512
    :return: returns the digest calculated with the chosen hmac function
    """

    try:
        primitive = cmacs[algorithm]
        c = cmac.CMAC(primitive(key), backend=default_backend())
        c.update(to_be_maced)
        digest = c.finalize()

        if algorithm == 'AES-MAC-256/64':
            # truncate the result to the first 64 bits
            digest = digest[:8]
    except KeyError:
        try:
            primitive = hmacs[algorithm]
            h = hmac.HMAC(key, primitive(), backend=default_backend())
            h.update(to_be_maced)
            digest = h.finalize()

            if algorithm == 'HS256/64':
                # truncate the result to the first 64 bits
                digest = digest[:8]

        except KeyError as e:
            raise CoseUnsupportedMAC("This cipher is not supported by the COSE specification: {}".format(e))

    return digest


def verify_tag_wrapper(key, tag, to_be_maced, algorithm):
    if algorithm != 'HS256/64':
        try:
            hash_primitive = hmacs[algorithm]
        except KeyError as e:
            raise CoseUnsupportedMAC("This cipher is not supported by the COSE specification: {}".format(e))

        h = hmac.HMAC(key, hash_primitive(), backend=default_backend())
        h.update(to_be_maced)
        h.verify(tag)
    elif algorithm == 'HS256/64':
        try:
            hash_primitive = hmacs[algorithm]
        except KeyError as e:
            raise CoseUnsupportedMAC("This cipher is not supported by the COSE specification: {}".format(e))

        h = hmac.HMAC(key, hash_primitive(), backend=default_backend())
        h.update(to_be_maced)
        if h.finalize()[:8] != tag:
            raise CoseInvalidTag("The authentication tags do not match")
    return True


def ec_sign_wrapper(key, to_be_signed, algorithm='ES256', curve='P-256'):
    if isinstance(key, str):
        signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    else:
        signer = key
    return signer.sign_deterministic(to_be_signed, hashfunc=hashes_for_ecc[algorithm])


def ec_verify_wrapper(key, to_be_signed, signature, algorithm='ES256', curve='P-256'):
    if isinstance(key, str):
        signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    else:
        signer = key
    try:
        verifier = signer.get_verifying_key()
    except AttributeError:
        verifier = signer
    return verifier.verify(signature, to_be_signed, hashfunc=hashes_for_ecc[algorithm])


def generate_crypto_keys(algorithm='ES256', curve='P-256'):
    if algorithm in ['ES256', 'ES384', 'ES512']:
        return keys.SigningKey.generate(ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
    if algorithm in ['HS256/64', 'HS256', 'HS384', 'HS512']:
        seed = get_randomness(64)
        key = hashes.Hash(hmacs[algorithm](), backend=default_backend())
        key.update(seed)
        return key.finalize()


def get_randomness(bytecount):
    return urandom(bytecount)
