from binascii import unhexlify, hexlify
from hashlib import sha256, sha512, sha384
from typing import Tuple, Union

from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDH, \
    SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import algorithms, aead, Cipher, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from ecdsa import NIST256p, NIST521p, NIST384p, SigningKey, VerifyingKey, ellipticcurve

from pycose.algorithms import AlgorithmIDs
from pycose.exceptions import *
from pycose.keys.cosekey import EllipticCurveTypes
from pycose.keys.ec import EC2
from pycose.keys.okp import OKP
from pycose.keys.symmetric import SymmetricKey

AESKW = {
    AlgorithmIDs.A128KW,
    AlgorithmIDs.A192KW,
    AlgorithmIDs.A256KW
}

ECDSA = {
    AlgorithmIDs.ES256: (NIST256p, sha256),
    AlgorithmIDs.ES384: (NIST384p, sha384),
    AlgorithmIDs.ES512: (NIST521p, sha512),
}

ECDH_HASHES = {
    AlgorithmIDs.ECDH_SS_HKDF_512: hashes.SHA512,
    AlgorithmIDs.ECDH_SS_HKDF_256: hashes.SHA256,
    AlgorithmIDs.ECDH_ES_HKDF_256: hashes.SHA256,
    AlgorithmIDs.ECDH_ES_HKDF_512: hashes.SHA512,
    AlgorithmIDs.ECDH_ES_A128KW: hashes.SHA256,
    AlgorithmIDs.ECDH_SS_A128KW: hashes.SHA256,
    AlgorithmIDs.ECDH_ES_A192KW: hashes.SHA256,
    AlgorithmIDs.ECDH_SS_A192KW: hashes.SHA256,
    AlgorithmIDs.ECDH_ES_A256KW: hashes.SHA256,
    AlgorithmIDs.ECDH_SS_A256KW: hashes.SHA256,
}

HMAC = {
    AlgorithmIDs.HMAC_256_64: hashes.SHA256,
    AlgorithmIDs.HMAC_256_256: hashes.SHA256,
    AlgorithmIDs.HMAC_384_384: hashes.SHA384,
    AlgorithmIDs.HMAC_512_512: hashes.SHA512,
}

HMAC_HASHES = {
    AlgorithmIDs.DIRECT_HKDF_SHA_256: hashes.SHA256,
    AlgorithmIDs.DIRECT_HKDF_SHA_512: hashes.SHA512,
}

AES_CBC_MAC = {
    AlgorithmIDs.AES_MAC_256_64: algorithms.AES,
    AlgorithmIDs.AES_MAC_128_64: algorithms.AES,
    AlgorithmIDs.AES_MAC_256_128: algorithms.AES,
    AlgorithmIDs.AES_MAC_128_128: algorithms.AES,
}

AEAD = {
    AlgorithmIDs.A128GCM: (aead.AESGCM, 16),
    AlgorithmIDs.A192GCM: (aead.AESGCM, 16),
    AlgorithmIDs.A256GCM: (aead.AESGCM, 16),
    AlgorithmIDs.AES_CCM_16_64_128: (aead.AESCCM, 8),
    AlgorithmIDs.AES_CCM_16_64_256: (aead.AESCCM, 8),
    AlgorithmIDs.AES_CCM_64_64_128: (aead.AESCCM, 8),
    AlgorithmIDs.AES_CCM_64_64_256: (aead.AESCCM, 8),
    AlgorithmIDs.AES_CCM_16_128_128: (aead.AESCCM, 16),
    AlgorithmIDs.AES_CCM_16_128_256: (aead.AESCCM, 16),
    AlgorithmIDs.AES_CCM_64_128_256: (aead.AESCCM, 16),
    AlgorithmIDs.AES_CCM_64_128_128: (aead.AESCCM, 16),
}

KEY_DERIVATION_CURVES = {
    EllipticCurveTypes.P_256: SECP256R1,
    EllipticCurveTypes.P_384: SECP384R1,
    EllipticCurveTypes.P_521: SECP521R1,
}


def aead_encrypt(key, aad, plaintext, algorithm, nonce):
    try:
        primitive, tag_length = AEAD[algorithm]
        if tag_length != 16:
            aead_cipher = primitive(key, tag_length=tag_length)
        else:
            aead_cipher = primitive(key)
        ciphertext = aead_cipher.encrypt(nonce=nonce, data=plaintext, associated_data=aad)
    except KeyError as err:
        raise CoseUnsupportedEnc("This cipher is not supported by the COSE specification: {}".format(err))

    return ciphertext


def aead_decrypt(key, aad, ciphertext, algorithm, nonce):
    try:
        primitive, tag_length = AEAD[algorithm]
        if tag_length != 16:
            aead_cipher = primitive(key, tag_length=tag_length)
        else:
            aead_cipher = primitive(key)
        plaintext = aead_cipher.decrypt(nonce, ciphertext, aad)
    except KeyError as err:
        raise CoseUnsupportedEnc("This cipher is not supported by the COSE specification: {}".format(err))

    return plaintext


def key_wrap(kek: bytes, plaintext_key: bytes) -> bytes:
    return aes_key_wrap(kek, plaintext_key, openssl.backend)


def key_unwrap(kek: bytes, wrapped_key: bytes) -> bytes:
    return aes_key_unwrap(kek, wrapped_key, openssl.backend)


def calc_tag_wrapper(key: bytes, to_be_maced: bytes, algorithm: AlgorithmIDs) -> bytes:
    """
    Wrapper function for the supported hmac in COSE
    :param key: key for computation of the hmac
    :param to_be_maced: byte string whose integrity need to be protected
    :param algorithm: chosen hmac, supports hmac with sha256, sha384 and sha512
    :return: returns the digest calculated with the chosen hmac function
    """

    try:
        primitive = AES_CBC_MAC[algorithm]
        encryptor = Cipher(
            primitive(key),
            modes.CBC(unhexlify(b"".join([b"00"] * 16))),
            backend=openssl.backend
        ).encryptor()

        padded = False
        while len(to_be_maced) % 16 != 0:
            to_be_maced += unhexlify(b"00")
            padded = True

        ciphertext = encryptor.update(to_be_maced) + encryptor.finalize()
        if padded:
            ciphertext = ciphertext[:-8]
        if algorithm in {AlgorithmIDs.AES_MAC_256_64, AlgorithmIDs.AES_MAC_128_64}:
            # truncate the result to the first 64 bits
            digest = ciphertext[-8:]
        else:
            digest = ciphertext[-16:]
    except KeyError:
        try:
            primitive = HMAC[algorithm]
            h = hmac.HMAC(key, primitive(), backend=default_backend())
            h.update(to_be_maced)
            digest = h.finalize()

            if algorithm == AlgorithmIDs.HMAC_256_64:
                # truncate the result to the first 64 bits
                digest = digest[:8]

        except KeyError as e:
            raise CoseUnsupportedMAC("This cipher is not supported by the COSE specification: {}".format(e))

    return digest


def verify_tag_wrapper(key, tag, to_be_maced, algorithm):
    computed_tag = calc_tag_wrapper(key, to_be_maced, algorithm)
    if tag != computed_tag:
        raise CoseInvalidTag("Invalid authentication tag: {} != {}".format(tag, computed_tag))
    return True


def ecdh_key_derivation(private_key: EllipticCurvePrivateKey,
                        public_key: EllipticCurvePublicKey,
                        alg: AlgorithmIDs,
                        length: int,
                        context: bytes = b'') -> Tuple[bytes, bytes]:
    shared_key = private_key.exchange(ECDH(), public_key)

    hash_func = ECDH_HASHES[alg]

    derived_key = HKDF(algorithm=hash_func(),
                       length=length,
                       salt=None,
                       info=context,
                       backend=openssl.backend).derive(shared_key)

    return shared_key, derived_key


def x25519_key_derivation(private_key: X25519PrivateKey,
                          public_key: X25519PublicKey,
                          alg: AlgorithmIDs,
                          length: int,
                          context: bytes = b'') -> Tuple[bytes, bytes]:
    shared_secret = private_key.exchange(public_key)

    hash_func = ECDH_HASHES[alg]

    derived_key = HKDF(algorithm=hash_func(),
                       length=length,
                       salt=None,
                       info=context,
                       backend=openssl.backend).derive(shared_secret)

    return shared_secret, derived_key


def hmac_hkdf_key_derivation(alg: AlgorithmIDs,
                             shared_secret: SymmetricKey,
                             length: int,
                             salt: bytes = None,
                             context: bytes = b''):
    hash_func = HMAC_HASHES[alg]

    derived_key = HKDF(algorithm=hash_func(),
                       length=length,
                       salt=salt,
                       info=context,
                       backend=openssl.backend).derive(shared_secret.key_bytes)

    return derived_key


def ec_sign_wrapper(key: Union[EC2, OKP], to_be_signed: bytes, algorithm: AlgorithmIDs) -> bytes:
    if algorithm in ECDSA:
        crv, hash_func = ECDSA[algorithm]
        sk = SigningKey.from_secret_exponent(int(hexlify(key.private_bytes), 16), curve=crv)

        return sk.sign_deterministic(to_be_signed, hashfunc=hash_func)
    else:
        # TODO: implement EdDSA
        return


def ec_verify_wrapper(key: Union[EC2, OKP], to_be_signed: bytes, signature: bytes, algorithm: AlgorithmIDs) -> bool:
    if algorithm in ECDSA:
        crv, hash_func = ECDSA[algorithm]
        p = ellipticcurve.Point(curve=crv.curve, x=int(hexlify(key.x), 16), y=int(hexlify(key.y), 16))
        vk = VerifyingKey.from_public_point(p, crv, hash_func, validate_point=True)

        return vk.verify(signature, to_be_signed)
