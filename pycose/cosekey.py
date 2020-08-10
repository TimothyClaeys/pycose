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
    _kty: Optional[KTY]
    _kid: Optional[Union[int, bytes]]
    _alg: Optional[CoseAlgorithm]
    _key_ops: Optional[KeyOps]
    _base_iv: Optional[bytes]

    KTY = {}

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
            cls.KTY[kty_id] = the_class
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
            return cls.KTY[received[cls.Common.KTY]].from_cose_key_obj(received)
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

    @property
    def kty(self) -> KTY:
        return self._kty

    @kty.setter
    def kty(self, new_kty: KTY) -> None:
        _ = KTY(new_kty)  # check if the new value is a known COSE KTY, should never be None!
        self._kty = new_kty

    @property
    def alg(self) -> Optional[CoseAlgorithm]:
        return self._alg

    @alg.setter
    def alg(self, new_alg: CoseAlgorithm) -> None:
        if new_alg is not None:
            _ = CoseAlgorithm(new_alg)  # check if the new value is a known COSE Algorithm
        self._alg = new_alg

    @property
    def kid(self) -> Optional[bytes]:
        return self._kid

    @kid.setter
    def kid(self, new_kid: bytes) -> None:
        if type(new_kid) is not bytes and new_kid is not None:
            raise ValueError("kid attribute must be of type 'bytes'")
        self._kid = new_kid

    @property
    def key_ops(self) -> Optional[KeyOps]:
        return self._key_ops

    @key_ops.setter
    def key_ops(self, new_key_ops: Optional[KeyOps]) -> None:
        if new_key_ops is not None:
            _ = KeyOps(new_key_ops)  # check if the new value is a known COSE key operation
        self._key_ops = new_key_ops

    @property
    def base_iv(self) -> Optional[bytes]:
        return self._base_iv

    @base_iv.setter
    def base_iv(self, new_base_iv: bytes) -> None:
        if new_base_iv is not None:
            _ = KeyOps(new_base_iv)  # check if the new value is a known COSE key operation
        self._base_iv = new_base_iv

    def encode(self, *argv) -> Dict[int, Union[int, bytes]]:
        key_words = [kw for kw in argv if self.Common.has_member(kw.upper())] + ['_kty']
        return {self.Common[kw[1:].upper()]: dc.asdict(self)[kw] for kw in key_words}

    @abstractmethod
    def __repr__(self):
        raise NotImplementedError


@CoseKey.record_kty(KTY.EC2)
@dc.dataclass(init=False)
class EC2(CoseKey):
    _crv: Optional[CoseEllipticCurves] = None
    _x: Optional[bytes] = None
    _y: Optional[bytes] = None
    _d: Optional[bytes] = None

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
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d

    @property
    def crv(self) -> Optional[CoseEllipticCurves]:
        return self._crv

    @crv.setter
    def crv(self, new_crv: Optional[CoseEllipticCurves]) -> None:
        if new_crv is not None:
            _ = CoseEllipticCurves(new_crv)
        self._crv = new_crv

    @property
    def x(self) -> bytes:
        return self._x

    @x.setter
    def x(self, new_x: Optional[bytes]) -> None:
        if type(new_x) is not bytes and new_x is not None:
            raise ValueError("public x coordinate must be of type 'bytes'")
        self._x = new_x

    @property
    def y(self) -> Optional[bytes]:
        return self._y

    @y.setter
    def y(self, new_y: Optional[bytes]) -> None:
        if type(new_y) is not bytes and new_y is not None:
            raise ValueError("public y coordinate must be of type 'bytes'")
        self._y = new_y

    @property
    def d(self) -> Optional[bytes]:
        return self._d

    @d.setter
    def d(self, new_d: Optional[bytes]) -> None:
        if type(new_d) is not bytes and new_d is not None:
            raise ValueError("private key must be of type 'bytes'")
        self._d = new_d

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
                    # store key coordinates as bytes
                    v = v
                key_obj[cls.EC2Prm(k)] = v

        return key_obj

    @property
    def public_bytes(self) -> Tuple[bytes, bytes]:
        return self.x, self.y

    @property
    def private_bytes(self) -> bytes:
        return self.d

    def encode(self, *argv):
        key_words = ['_' + kw for kw in argv if self.EC2Prm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.EC2Prm[kw[1:].upper()]: dc.asdict(self)[kw] for kw in key_words}}

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
    _crv: Optional[CoseEllipticCurves] = None
    _x: Optional[bytes] = None
    _d: Optional[bytes] = None

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
        self.crv = crv
        self.x = x
        self.d = d

    @property
    def crv(self) -> Optional[CoseEllipticCurves]:
        return self._crv

    @crv.setter
    def crv(self, new_crv: Optional[CoseEllipticCurves]) -> None:
        if new_crv is not None:
            _ = CoseEllipticCurves(new_crv)
        self._crv = new_crv

    @property
    def x(self) -> Optional[bytes]:
        return self._x

    @x.setter
    def x(self, new_x: Optional[bytes]) -> None:
        if type(new_x) is not bytes and new_x is not None:
            raise ValueError("public x coordinate must be of type 'bytes'")
        self._x = new_x

    @property
    def d(self) -> Optional[bytes]:
        return self._d

    @d.setter
    def d(self, new_d: Optional[bytes]) -> None:
        if type(new_d) is not bytes and new_d is not None:
            raise ValueError("private key must be of type 'bytes'")
        self._d = new_d

    @property
    def public_bytes(self) -> Optional[bytes]:
        return self.x

    @property
    def private_bytes(self) -> Optional[bytes]:
        return self.d

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
                    # store key coordinates as bytes
                    v = v
                key_obj[cls.OKPPrm(k)] = v

        return key_obj

    def encode(self, *argv):
        key_words = [kw for kw in argv if self.OKPPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.OKPPrm[kw.upper()]: dc.asdict(self)[kw] for kw in key_words}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(OKP)>']
        output.extend(self._base_repr(k, v) if k not in [-2, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)


@CoseKey.record_kty(KTY.SYMMETRIC)
@dc.dataclass(init=False)
class SymmetricKey(CoseKey):
    k: Optional[bytes] = None

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
        self.k = k

    @property
    def key_bytes(self):
        return self.k

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> dict:
        """Returns an initialized COSE_Key object."""

        key_obj = super().from_cose_key_obj(cose_key_obj)

        if cls.SymPrm.K in cose_key_obj:
            key_obj[cls.SymPrm.K] = hexlify(key_obj[cls.SymPrm.K])

        return key_obj

    def encode(self, *argv):
        key_words = [kw for kw in argv if self.SymPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.SymPrm[kw.upper()]: dc.asdict(self)[kw] for kw in key_words}}

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
