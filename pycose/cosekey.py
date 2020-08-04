from abc import ABCMeta
from enum import IntEnum, unique
from typing import List


@unique
class KTY(IntEnum):
    RESERVED = 0
    OKP = 1
    EC2 = 2
    SYMMETRIC = 4


@unique
class ECParam(IntEnum):
    CRV = -1
    X = -2
    Y = - 3
    D = -4


@unique
class OKPParam(IntEnum):
    CRV = -1
    X = -2
    D = -4


@unique
class CoseKeyParam(IntEnum):
    KTY = 1
    KID = 2
    ALG = 3
    KEY_OPS = 4
    BASE_IV = 5


@unique
class KeyOps(IntEnum):
    SIGN = 1
    VERIFY = 2
    ENCRYPT = 3
    DECRYPT = 4
    WRAP = 5
    UNWRAP = 6
    DERIVE_KEY = 7
    DERIVE_BITS = 8
    MAC_CREATE = 9
    MAC_VERIFY = 10


@unique
class CoseEllipticCurves(IntEnum):
    RESERVED = 0
    P_256 = 1
    P_384 = 2
    P_521 = 3
    X25519 = 4
    X448 = 5
    ED25519 = 6
    ED448 = 7
    SECP256K1 = 8


@unique
class SymmetricParam(IntEnum):
    K = -1


@unique
class EcdhAlgorithmParam(IntEnum):
    EPHEMERAL_KEY = -1
    STATIC_KEY = - 2
    STATIC_KEY_ID = -3


class CoseKey(metaclass=ABCMeta):
    @property
    def kty(self):
        raise NotImplementedError

    def __init__(self, kid: bytes = None, alg: int = None, key_ops: int = None, base_iv: bytes = None):
        self.kid = kid
        self.alg = alg
        self.key_ops = key_ops
        self.base_iv = base_iv


class CoseKeySet:
    def __init__(self, cose_keys: List[CoseKey] = None):
        if cose_keys is None:
            self.cose_keys = []
        else:
            self.cose_keys = cose_keys


class EC2(CoseKey):
    kty = KTY.EC2

    def __init__(self, crv, x: bytes, y: bytes, d: bytes, kid: bytes, alg: int, key_ops: int, base_iv: bytes):
        super().__init__(kid, alg, key_ops, base_iv)
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d


class OKP(CoseKey):
    """
    Octet Key Pairs: Do not assume that keys using this type are elliptic curves.  This key type could be used for
    other curve types.
    """
    kty = KTY.OKP

    def __init__(self, crv, x: bytes, d: bytes, kid, alg, key_ops, base_iv):
        super().__init__(kid, alg, key_ops, base_iv)
        self.crv = crv
        self.x = x
        self.d = d


class SymmetricKeys(CoseKey):
    kty = KTY.SYMMETRIC

    def __init__(self, k, kid, alg, key_ops, base_iv):
        super().__init__(kid, alg, key_ops, base_iv)
        self.k = k
