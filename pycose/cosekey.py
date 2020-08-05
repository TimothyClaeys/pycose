import dataclasses as dc
from abc import ABCMeta
from enum import IntEnum, unique
from typing import List, Union, Dict


@unique
class KTY(IntEnum):
    RESERVED = 0
    OKP = 1
    EC2 = 2
    SYMMETRIC = 4


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


@dc.dataclass
class CoseKey(metaclass=ABCMeta):
    KTY: int
    KID: Union[int, bytes]
    ALG: int
    KEY_OPS: int
    BASE_IV: bytes

    class Common(IntEnum):
        KTY = 1
        KID = 2
        ALG = 3
        KEY_OPS = 4
        BASE_IV = 5

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def encode(self) -> Dict[int, Union[int, bytes]]:
        return {self.Common[k]: v for k, v in dc.asdict(self).items() if v is not None and self.Common.has_member(k)}


@dc.dataclass(init=False)
class EC2(CoseKey):
    CRV: int = None
    X: bytes = None
    Y: bytes = None
    D: bytes = None

    class EC2Prm(IntEnum):
        CRV = -1
        X = -2
        Y = -3
        D = -4

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 crv: int = None, x: bytes = None, y: bytes = None, d: bytes = None):
        super().__init__(KTY.EC2, kid, alg, key_ops, base_iv)
        self.CRV = crv
        self.X = x
        self.Y = y
        self.D = d

    def encode(self):
        b = super().encode()
        b.update({self.EC2Prm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.EC2Prm.has_member(k)})
        return b


@dc.dataclass(init=False)
class OKP(CoseKey):
    """
    Octet Key Pairs: Do not assume that keys using this type are elliptic curves.  This key type could be used for
    other curve types.
    """
    CRV: int = None
    X: bytes = None
    D: bytes = None

    class OKPPrm(IntEnum):
        CRV = -1
        X = -2
        D = -4

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 crv: int = None, x: bytes = None, d: bytes = None):
        super().__init__(KTY.OKP, kid, alg, key_ops, base_iv)
        self.CRV = crv
        self.X = x
        self.D = d

    def encode(self):
        b = super().encode()
        b.update({self.OKPPrm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.OKPPrm.has_member(k)})
        return b


@dc.dataclass(init=False)
class SymmetricKey(CoseKey):
    K: bytes = None

    class SymPrm(IntEnum):
        K = - 1

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self, kid: Union[int, bytes] = None, alg: int = None, key_ops: int = None, base_iv: bytes = None,
                 k: bytes = None):
        super().__init__(KTY.OKP, kid, alg, key_ops, base_iv)
        self.K = k

    @property
    def keybytes(self):
        return self.K

    def encode(self):
        b = super().encode()
        b.update({self.SymPrm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.SymPrm.has_member(k)})
        return b


class CoseKeySet:
    def __init__(self, cose_keys: List[CoseKey] = None):
        if cose_keys is None:
            self.cose_keys = []
        else:
            self.cose_keys = cose_keys


if __name__ == "__main__":
    print(EC2(crv=EllipticCurveKeys.P_256).encode())
