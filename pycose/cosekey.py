from abc import ABCMeta, abstractmethod
from enum import IntEnum, unique
from typing import List, Union, Dict

import dataclasses
from dataclasses import dataclass


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


@unique
class EllipticCurveKeys(IntEnum):
    P_256 = 1
    P_384 = 2
    P_521 = 3
    X25519 = 4
    X448 = 5
    ED25519 = 6
    ED448 = 7


@dataclass
class CoseKey(metaclass=ABCMeta):
    kid: Union[int, str]
    alg: int
    key_ops: int
    base_iv: bytes

    @unique
    class Param(IntEnum):
        KTY = 1
        KID = 2
        ALG = 3
        KEY_OPS = 4
        BASE_IV = 5

    @abstractmethod
    def encode(self) -> Dict[Param, Union[int, bytes]]:
        return {self.Param[k.name.upper()]: getattr(self, k.name) for k in dataclasses.fields(CoseKey) if
                getattr(self, k.name) is not None}

    def _check(self, attr):
        return getattr(self, attr) is not None and attr not in CoseKey.__dict__['__annotations__']


@dataclass(init=False)
class EC2(CoseKey):
    crv: int = None
    x: bytes = None
    y: bytes = None
    d: bytes = None

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 crv: int = None, x: bytes = None, y: bytes = None, d: bytes = None):
        self.key_params = {CoseKeyParam.KTY: KTY.EC2}

        self.alg = alg
        self.kid = kid
        self.key_ops = key_ops
        self.base_iv = base_iv
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d

    def encode(self) -> Dict[int, Union[int, bytes]]:
        base = super().encode()
        self.key_params.update(base)

        local = \
            {ECParam[k.name.upper()]: getattr(self, k.name) for k in dataclasses.fields(EC2) if self._check(k.name)}
        self.key_params.update(local)
        return self.key_params


@dataclass(init=False)
class OKP(CoseKey):
    """
    Octet Key Pairs: Do not assume that keys using this type are elliptic curves.  This key type could be used for
    other curve types.
    """
    crv: int = None
    x: bytes = None
    d: bytes = None

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 crv: int = None, x: bytes = None, d: bytes = None):
        self.key_params = {CoseKeyParam.KTY: KTY.OKP}

        self.alg = alg
        self.kid = kid
        self.key_ops = key_ops
        self.base_iv = base_iv
        self.crv = crv
        self.x = x
        self.d = d

    def encode(self) -> Dict[int, Union[int, bytes]]:
        base = super().encode()
        self.key_params.update(base)

        local = \
            {OKPParam[k.name.upper()]: getattr(self, k.name) for k in dataclasses.fields(OKP) if self._check(k.name)}
        self.key_params.update(local)
        return self.key_params


class SymmetricKey(CoseKey):
    kty = KTY.SYMMETRIC

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 k: bytes = None):
        self.key_params = {CoseKeyParam.KTY: KTY.SYMMETRIC}

        self.alg = alg
        self.kid = kid
        self.key_ops = key_ops
        self.base_iv = base_iv
        self.k = k

    def encode(self) -> Dict[int, Union[int, bytes]]:
        pass


class CoseKeySet:
    def __init__(self, cose_keys: List[CoseKey] = None):
        if cose_keys is None:
            self.cose_keys = []
        else:
            self.cose_keys = cose_keys


if __name__ == "__main__":
    print(EC2(crv=EllipticCurveKeys.P_256).encode())
