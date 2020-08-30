from hashlib import sha512, sha384, sha256
from typing import Any, Optional, NamedTuple, List, Union

from aenum import MultiValue, Enum, skip
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, SECP256K1
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import SHA384, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import NIST521p, NIST384p, NIST256p, SECP256k1


class _AlgorithmConfig(NamedTuple):
    primitive: Any = None
    kdf: Any = None
    curve: Any = None
    tag_length: Optional[int] = None
    hash: Any = None


class CoseAlgorithms(Enum):
    _init_ = 'id fullname config'
    _settings_ = MultiValue

    ES512 = -36, 'ES512', skip(_AlgorithmConfig(curve=NIST521p, hash=sha512))
    ES384 = -35, 'ES384', skip(_AlgorithmConfig(curve=NIST384p, hash=sha384))
    ECDH_SS_A256KW = -34, 'ECDH_SS_A256KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_SS_A192KW = -33, 'ECDH_SS_A192KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_SS_A128KW = -32, 'ECDH_SS_A128KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_ES_A256KW = -31, 'ECDH_ES_A256KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_ES_A192KW = -30, 'ECDH_ES_A192KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_ES_A128KW = -29, 'ECDH_ES_A128KW', skip(_AlgorithmConfig(primitive=keywrap, kdf=HKDF, hash=SHA256))
    ECDH_SS_HKDF_512 = -28, 'ECDH_SS_HKDF_512', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA512))
    ECDH_SS_HKDF_256 = -27, 'ECDH_SS_HKDF_256', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA256))
    ECDH_ES_HKDF_512 = -26, 'ECDH_ES_HKDF_512', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA512))
    ECDH_ES_HKDF_256 = -25, 'ECDH_ES_HKDF_256', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA256))
    # SHAKE_128 = -18
    # SHA_512_256 = -17
    SHA_256 = -16, 'SHA_256', skip(_AlgorithmConfig(hash=SHA256))
    # SHA_256_64 = -15
    # SHA_1 = -14
    # DIRECT_HKDF_AES_256 = -13
    # DIRECT_HKDF_AES_128 = -12
    DIRECT_HKDF_SHA_512 = -11, 'DIRECT_HKDF_SHA_512', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA512))
    DIRECT_HKDF_SHA_256 = -10, 'DIRECT_HKDF_SHA_256', skip(_AlgorithmConfig(kdf=HKDF, hash=SHA256))
    EDDSA = -8, 'EdDSA', skip(_AlgorithmConfig(hash=SHA256))
    ES256 = -7, 'ES256', skip(_AlgorithmConfig(curve=NIST256p, hash=sha256))
    DIRECT = -6, 'Direct', skip(_AlgorithmConfig())
    A256KW = -5, 'A256KW', skip(_AlgorithmConfig(primitive=keywrap))
    A192KW = -4, 'A192KW', skip(_AlgorithmConfig(primitive=keywrap))
    A128KW = -3, 'A128KW', skip(_AlgorithmConfig(primitive=keywrap))
    A128GCM = 1, 'A128GCM', skip(_AlgorithmConfig(primitive=AESGCM))
    A192GCM = 2, 'A192GCM', skip(_AlgorithmConfig(primitive=AESGCM))
    A256GCM = 3, 'A256GCM', skip(_AlgorithmConfig(primitive=AESGCM))
    HMAC_256_64 = 4, 'HMAC_256_64', skip(_AlgorithmConfig(primitive=HMAC, tag_length=8, hash=SHA256))
    HMAC_256_256 = 5, 'HMAC_256_256', skip(_AlgorithmConfig(primitive=HMAC, hash=SHA256))
    HMAC_384_384 = 6, 'HMAC_256_384', skip(_AlgorithmConfig(primitive=HMAC, hash=SHA384))
    HMAC_512_512 = 7, 'HMAC_256_512', skip(_AlgorithmConfig(primitive=HMAC, hash=SHA512))
    AES_CCM_16_64_128 = 10, 'AES_CCM_16_64_128', skip(_AlgorithmConfig(primitive=AESCCM, tag_length=8))
    AES_CCM_16_64_256 = 11, 'AES_CCM_16_64_256', skip(_AlgorithmConfig(primitive=AESCCM, tag_length=8))
    AES_CCM_64_64_128 = 12, 'AES_CCM_64_64_128', skip(_AlgorithmConfig(primitive=AESCCM, tag_length=8))
    AES_CCM_64_64_256 = 13, 'AES_CCM_64_64_256', skip(_AlgorithmConfig(primitive=AESCCM, tag_length=8))
    AES_MAC_128_64 = 14, 'AES_MAC_128_64', skip(_AlgorithmConfig(primitive=AES, tag_length=8))
    AES_MAC_256_64 = 15, 'AES_MAC_256_64', skip(_AlgorithmConfig(primitive=AES, tag_length=8))
    # # CHACHA20_POLY1305 = 24
    AES_MAC_128_128 = 25, 'AES_MAC_128_128', skip(_AlgorithmConfig(primitive=AES))
    AES_MAC_256_128 = 26, 'AES_MAC_256_128', skip(_AlgorithmConfig(primitive=AES))
    AES_CCM_16_128_128 = 30, 'AES_CCM_16_128_128', skip(_AlgorithmConfig(primitive=AESCCM))
    AES_CCM_16_128_256 = 31, 'AES_CCM_16_128_256', skip(_AlgorithmConfig(primitive=AESCCM))
    AES_CCM_64_128_128 = 32, 'AES_CCM_64_128_128', skip(_AlgorithmConfig(primitive=AESCCM))
    AES_CCM_64_128_256 = 33, 'AES_CCM_64_128_256', skip(_AlgorithmConfig(primitive=AESCCM))

    def __int__(self):
        return self.id

    def __str__(self):
        return self.fullname

    def __repr__(self):
        return f'<{self.__class__.__name__}.{self.fullname}: {self.id}>'

    def __eq__(self, other):
        return self.id == other or self.fullname == other

    def __hash__(self):
        return hash((self.id, self.fullname))


class CoseEllipticCurves(Enum):
    """ The (elliptic) curves supported by COSE. """

    _init_ = 'id fullname config'
    _settings_ = MultiValue

    RESERVED = 0, 'RESERVED', skip(_AlgorithmConfig())
    P_256 = 1, 'P_256', skip(_AlgorithmConfig(curve=(NIST256p, SECP256R1)))
    P_384 = 2, 'P_384', skip(_AlgorithmConfig(curve=(NIST384p, SECP384R1)))
    P_521 = 3, 'P_521', skip(_AlgorithmConfig(curve=(NIST521p, SECP521R1)))
    X25519 = 4, 'X25519', skip(_AlgorithmConfig())
    X448 = 5, 'X448', skip(_AlgorithmConfig())
    ED25519 = 'Ed25519', 6, skip(_AlgorithmConfig())
    ED448 = 7, 'Ed448', skip(_AlgorithmConfig())
    SECP256K1 = 8, 'SECP256K1', skip(_AlgorithmConfig(curve=(SECP256k1, SECP256K1)))

    def __int__(self):
        return self.id

    def __str__(self):
        return self.fullname

    def __repr__(self):
        return f'<{self.__class__.__name__}.{self.fullname}: {self.id}>'

    def __eq__(self, other):
        return self.id == other or self.fullname == other

    def __hash__(self):
        return hash((self.id, self.fullname))


def config(algorithm: Union[CoseAlgorithms, CoseEllipticCurves]) -> _AlgorithmConfig:
    return algorithm.config.value


def list_ciphers() -> List[CoseAlgorithms]:
    return [k for k in CoseAlgorithms.__members__.keys()]


def list_curves() -> List[CoseEllipticCurves]:
    return [k for k in CoseEllipticCurves.__members__.keys()]
