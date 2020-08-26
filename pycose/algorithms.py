from enum import unique, IntEnum, Enum
from hashlib import sha256, sha384, sha512
from typing import Any

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import SHA384, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dataclasses import dataclass
from ecdsa import NIST521p, NIST384p, NIST256p


@unique
class AlgorithmIDs(IntEnum):
    ES512 = -36
    ES384 = -35
    ECDH_SS_A256KW = -34
    ECDH_SS_A192KW = -33
    ECDH_SS_A128KW = -32
    ECDH_ES_A256KW = -31
    ECDH_ES_A192KW = -30
    ECDH_ES_A128KW = -29
    ECDH_SS_HKDF_512 = -28
    ECDH_SS_HKDF_256 = -27
    ECDH_ES_HKDF_512 = -26
    ECDH_ES_HKDF_256 = -25
    # SHAKE_128 = -18
    # SHA_512_256 = -17
    SHA_256 = -16
    SHA_256_64 = -15
    # SHA_1 = -14
    # DIRECT_HKDF_AES_256 = -13
    # DIRECT_HKDF_AES_128 = -12
    DIRECT_HKDF_SHA_512 = -11
    DIRECT_HKDF_SHA_256 = -10
    EDDSA = -8
    ES256 = -7
    DIRECT = -6
    A256KW = -5
    A192KW = -4
    A128KW = -3
    A128GCM = 1
    A192GCM = 2
    A256GCM = 3
    HMAC_256_64 = 4
    HMAC_256_256 = 5
    HMAC_384_384 = 6
    HMAC_512_512 = 7
    AES_CCM_16_64_128 = 10
    AES_CCM_16_64_256 = 11
    AES_CCM_64_64_128 = 12
    AES_CCM_64_64_256 = 13
    AES_MAC_128_64 = 14
    AES_MAC_256_64 = 15
    # CHACHA20_POLY1305 = 24
    AES_MAC_128_128 = 25
    AES_MAC_256_128 = 26
    AES_CCM_16_128_128 = 30
    AES_CCM_16_128_256 = 31
    AES_CCM_64_128_128 = 32
    AES_CCM_64_128_256 = 33


@dataclass
class AlgoParam:
    primitive: Any = None
    key_derivation: Any = None
    curve: Any = None
    tag_length: int = None
    hash: Any = None


class AlgID2Crypto(Enum):
    ES512 = AlgoParam(hash=sha512, curve=NIST521p)
    ES384 = AlgoParam(hash=sha384, curve=NIST384p)
    ECDH_SS_A256KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_SS_A192KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_SS_A128KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_ES_A256KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_ES_A192KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_ES_A128KW = AlgoParam(primitive=keywrap, key_derivation=HKDF, hash=SHA256)
    ECDH_SS_HKDF_512 = AlgoParam(key_derivation=HKDF, hash=SHA512)
    ECDH_SS_HKDF_256 = AlgoParam(key_derivation=HKDF, hash=SHA256)
    ECDH_ES_HKDF_512 = AlgoParam(key_derivation=HKDF, hash=SHA512)
    ECDH_ES_HKDF_256 = AlgoParam(key_derivation=HKDF, hash=SHA256)
    # DIRECT_HKDF_AES_256 = -13
    # DIRECT_HKDF_AES_128 = -12
    SHA_256 = AlgoParam(hash=SHA256)
    SHA_256_64 = AlgoParam(hash=SHA256, tag_length=8)
    DIRECT_HKDF_SHA_512 = AlgoParam(key_derivation=HKDF, hash=SHA512)
    DIRECT_HKDF_SHA_256 = AlgoParam(key_derivation=HKDF, hash=SHA256)
    EDDSA = AlgoParam(hash=SHA256)
    ES256 = AlgoParam(hash=sha256, curve=NIST256p)
    DIRECT = AlgoParam()
    A256KW = AlgoParam(primitive=keywrap)
    A192KW = AlgoParam(primitive=keywrap)
    A128KW = AlgoParam(primitive=keywrap)
    A128GCM = AlgoParam(primitive=AESGCM)
    A192GCM = AlgoParam(primitive=AESGCM)
    A256GCM = AlgoParam(primitive=AESGCM)
    HMAC_256_64 = AlgoParam(primitive=HMAC, hash=SHA256)
    HMAC_256_256 = AlgoParam(primitive=HMAC, hash=SHA256)
    HMAC_384_384 = AlgoParam(primitive=HMAC, hash=SHA384)
    HMAC_512_512 = AlgoParam(primitive=HMAC, hash=SHA512)
    AES_CCM_16_64_128 = AlgoParam(primitive=AESCCM, tag_length=8)
    AES_CCM_16_64_256 = AlgoParam(primitive=AESCCM, tag_length=8)
    AES_CCM_64_64_128 = AlgoParam(primitive=AESCCM, tag_length=8)
    AES_CCM_64_64_256 = AlgoParam(primitive=AESCCM, tag_length=8)
    AES_MAC_128_64 = AlgoParam(primitive=AES, tag_length=8)
    AES_MAC_256_64 = AlgoParam(primitive=AES, tag_length=8)
    # CHACHA20_POLY1305 = 24
    AES_MAC_128_128 = AlgoParam(primitive=AES)
    AES_MAC_256_128 = AlgoParam(primitive=AES)
    AES_CCM_16_128_128 = AlgoParam(primitive=AESCCM)
    AES_CCM_16_128_256 = AlgoParam(primitive=AESCCM)
    AES_CCM_64_128_128 = AlgoParam(primitive=AESCCM)
    AES_CCM_64_128_256 = AlgoParam(primitive=AESCCM)
