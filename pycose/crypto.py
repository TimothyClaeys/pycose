from binascii import unhexlify
from typing import Tuple

import cbor2
from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDH, \
    SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import algorithms, aead, Cipher, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from dataclasses import dataclass

from pycose.attributes import CoseAlgorithm
from pycose.cosekey import CoseEllipticCurves
from pycose.exceptions import *

AESKW = {
    CoseAlgorithm.A128KW,
    CoseAlgorithm.A192KW,
    CoseAlgorithm.A256KW
}

ECDH_HASHES = {
    CoseAlgorithm.ECDH_SS_HKDF_512: hashes.SHA512,
    CoseAlgorithm.ECDH_SS_HKDF_256: hashes.SHA256,
    CoseAlgorithm.ECDH_ES_HKDF_256: hashes.SHA256,
    CoseAlgorithm.ECDH_ES_HKDF_512: hashes.SHA512,
    CoseAlgorithm.ECDH_ES_A128KW: hashes.SHA256,
    CoseAlgorithm.ECDH_SS_A128KW: hashes.SHA256,
    CoseAlgorithm.ECDH_ES_A192KW: hashes.SHA256,
    CoseAlgorithm.ECDH_SS_A192KW: hashes.SHA256,
    CoseAlgorithm.ECDH_ES_A256KW: hashes.SHA256,
    CoseAlgorithm.ECDH_SS_A256KW: hashes.SHA256,
}

HMAC = {
    CoseAlgorithm.HMAC_256_64: hashes.SHA256,
    CoseAlgorithm.HMAC_256_256: hashes.SHA256,
    CoseAlgorithm.HMAC_384_384: hashes.SHA384,
    CoseAlgorithm.HMAC_512_512: hashes.SHA512,
}

AES_CBC_MAC = {
    CoseAlgorithm.AES_MAC_256_64: algorithms.AES,
    CoseAlgorithm.AES_MAC_128_64: algorithms.AES,
    CoseAlgorithm.AES_MAC_256_128: algorithms.AES,
    CoseAlgorithm.AES_MAC_128_128: algorithms.AES,
}

AEAD = {
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

KEY_DERIVATION_CURVES = {
    CoseEllipticCurves.P_256: SECP256R1,
    CoseEllipticCurves.P_384: SECP384R1,
    CoseEllipticCurves.P_521: SECP521R1,
}


@dataclass
class PartyInfo:
    identity: bytes = None
    nonce: bytes = None
    other: bytes = None

    def encode(self):
        return [self.identity, self.nonce, self.other]


@dataclass
class SuppPubInfo:
    _key_data_length: int
    protected: bytes
    other: bytes = None

    @property
    def key_data_length(self):
        return self._key_data_length

    @key_data_length.setter
    def key_data_length(self, new_length):
        if new_length in [128, 192, 256]:
            self._key_data_length = new_length
        else:
            raise ValueError(f"Not a valid key length: {new_length}")

    def __post__init__(self):
        if self._key_data_length not in [128, 192, 256]:
            raise ValueError(f"Not a valid key length: {self._key_data_length}")

    def encode(self):
        info = [self.key_data_length, self.protected]
        if self.other is not None:
            info.append(self.other)

        return info


@dataclass
class CoseKDFContext:
    algorithm_id: int
    party_u_info: PartyInfo
    party_v_info: PartyInfo
    supp_pub_info: SuppPubInfo
    supp_priv_info: bytes = None

    def encode(self):
        context = \
            [self.algorithm_id, self.party_u_info.encode(), self.party_v_info.encode(), self.supp_pub_info.encode()]
        if self.supp_priv_info is not None:
            context.append(self.supp_priv_info)
        return cbor2.dumps(context)


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


def calc_tag_wrapper(key: bytes, to_be_maced: bytes, algorithm: CoseAlgorithm) -> bytes:
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
        if algorithm in {CoseAlgorithm.AES_MAC_256_64, CoseAlgorithm.AES_MAC_128_64}:
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

            if algorithm == CoseAlgorithm.HMAC_256_64:
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
                        alg: CoseAlgorithm,
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
                          alg: CoseAlgorithm,
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

# def ec_sign_wrapper(key, to_be_signed, algorithm, curve):
#     if isinstance(key, str):
#         signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
#     else:
#         signer = key
#     return signer.sign_deterministic(to_be_signed, hashfunc=hashes_for_ecc[algorithm])
#
#
# def ec_verify_wrapper(key, to_be_signed, signature, algorithm='ES256', curve='P-256'):
#     if isinstance(key, str):
#         signer = derive_priv_key(key, ec_curves[curve], hashfunc=hashes_for_ecc[algorithm])
#     else:
#         signer = key
#     try:
#         verifier = signer.get_verifying_key()
#     except AttributeError:
#         verifier = signer
#     return verifier.verify(signature, to_be_signed, hashfunc=hashes_for_ecc[algorithm])
