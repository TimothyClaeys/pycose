import base64
from abc import ABCMeta, abstractmethod
from binascii import hexlify
from enum import IntEnum, unique
from typing import List, Union, Dict, Optional, Tuple

import dataclasses as dc

from pycose.attributes import CoseAlgorithm


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
    KTY: Optional[int]
    KID: Optional[Union[int, bytes]]
    ALG: Optional[int]
    KEY_OPS: Optional[int]
    BASE_IV: Optional[bytes]

    kty = {}

    class Common(IntEnum):
        KTY = 1
        KID = 2
        ALG = 3
        KEY_OPS = 4
        BASE_IV = 5

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    @classmethod
    def record_kty(cls, kty_id: int):
        """Decorator to record all the CBOR tags dynamically"""

        def decorator(the_class):
            if not issubclass(the_class, CoseKey):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls.kty[kty_id] = the_class
            return the_class

        return decorator

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = {}
        values = set(item.value for item in cls.Common)

        for k, v in cose_key_obj.items():
            if k in values:
                if k == cls.Common.ALG:
                    v = CoseAlgorithm(v)
                elif k == cls.Common.KTY:
                    v = KTY(v)
                elif k == cls.Common.KEY_OPS:
                    v = KeyOps(v)
                else:
                    v = hexlify(v)
                key_obj[cls.Common(k)] = v

        return key_obj

    @classmethod
    def decode(cls, received: dict):
        try:
            return cls.kty[received[cls.Common.KTY]].from_cose_key_obj(received)
        except KeyError as e:
            raise KeyError("Key type identifier is not recognized", e)

    @staticmethod
    def base64decode(to_decode: str) -> bytes:
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

    @classmethod
    def _base_repr(cls, k: int, v: bytes) -> str:
        return f"\t{repr(k):<16} = {repr(v)}"

    @classmethod
    def _key_repr(cls, k: int, v: bytes) -> str:
        return f"\t{repr(k):<16} = {hexlify(v)}"

    def encode(self) -> Dict[int, Union[int, bytes]]:
        return {self.Common[k]: v for k, v in dc.asdict(self).items() if v is not None and self.Common.has_member(k)}

    @abstractmethod
    def __repr__(self):
        raise NotImplementedError


@CoseKey.record_kty(KTY.EC2)
@dc.dataclass(init=False)
class EC2(CoseKey):
    CRV: Optional[int] = None
    X: Optional[bytes] = None
    Y: Optional[bytes] = None
    D: Optional[bytes] = None

    class EC2Prm(IntEnum):
        CRV = -1
        X = -2
        Y = -3
        D = -4

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self,
                 kid: Optional[Union[int, bytes]] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 crv: Optional[int] = None,
                 x: Optional[bytes] = None,
                 y: Optional[bytes] = None,
                 d: Optional[bytes] = None):
        super().__init__(KTY.EC2, kid, alg, key_ops, base_iv)
        self.CRV = crv
        self.X = x
        self.Y = y
        self.D = d

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)
        values = set(item.value for item in cls.EC2Prm)

        for k, v in cose_key_obj.items():
            if k in values:
                if k == cls.EC2Prm.CRV:
                    v = EllipticCurveKeys(v)
                else:
                    v = hexlify(v)
                key_obj[cls.EC2Prm(k)] = v

        return key_obj

    @property
    def public_bytes(self) -> Tuple[bytes, bytes]:
        return self.X, self.Y

    @property
    def private_bytes(self) -> bytes:
        return self.D

    def encode(self):
        b = super().encode()
        b.update({self.EC2Prm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.EC2Prm.has_member(k)})
        return b

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(EC2)>']
        output.extend(
            self._base_repr(k, v) if k not in [-2, -3, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)


@CoseKey.record_kty(KTY.OKP)
@dc.dataclass(init=False)
class OKP(CoseKey):
    """
    Octet Key Pairs: Do not assume that keys using this type are elliptic curves.  This key type could be used for
    other curve types.
    """
    CRV: Optional[int] = None
    X: Optional[bytes] = None
    D: Optional[bytes] = None

    class OKPPrm(IntEnum):
        CRV = -1
        X = -2
        D = -4

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self,
                 kid: Optional[Union[int, bytes]] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 crv: Optional[int] = None,
                 x: Optional[bytes] = None,
                 d: Optional[bytes] = None):
        super().__init__(KTY.OKP, kid, alg, key_ops, base_iv)
        self.CRV = crv
        self.X = x
        self.D = d

    @property
    def public_bytes(self) -> bytes:
        return self.X

    @property
    def private_bytes(self) -> bytes:
        return self.D

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)
        values = set(item.value for item in cls.OKPPrm)

        for k, v in cose_key_obj.items():
            if k in values:
                if k == cls.OKPPrm.CRV:
                    v = EllipticCurveKeys(v)
                else:
                    v = hexlify(v)
                key_obj[cls.OKPPrm(k)] = v

        return key_obj

    def encode(self):
        b = super().encode()
        b.update({self.OKPPrm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.OKPPrm.has_member(k)})
        return b

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(OKP)>']
        output.extend(self._base_repr(k, v) if k not in [-2, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)


@CoseKey.record_kty(KTY.SYMMETRIC)
@dc.dataclass(init=False)
class SymmetricKey(CoseKey):
    K: Optional[bytes] = None

    class SymPrm(IntEnum):
        K = - 1

        @classmethod
        def has_member(cls, item):
            return item in cls.__members__

    def __init__(self,
                 kid: Optional[Union[int, bytes]] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 k: Optional[bytes] = None):
        super().__init__(KTY.SYMMETRIC, kid, alg, key_ops, base_iv)
        self.K = k

    @property
    def key_bytes(self):
        return self.K

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)

        if cls.SymPrm.K in cose_key_obj:
            key_obj[cls.SymPrm.K] = hexlify(key_obj[cls.SymPrm.K])

        return key_obj

    def encode(self):
        b = super().encode()
        b.update({self.SymPrm[k]: v for k, v in dc.asdict(self).items() if v is not None and self.SymPrm.has_member(k)})
        return b

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(SymmetricKey)>']
        output.extend(self._base_repr(k, v) if k not in [-1] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)


class CoseKeySet:
    def __init__(self, cose_keys: List[CoseKey] = None):
        if cose_keys is None:
            self.cose_keys = []
        else:
            self.cose_keys = cose_keys

