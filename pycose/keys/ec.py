from enum import IntEnum
from typing import Optional, Tuple

import dataclasses
from dataclasses import dataclass

from pycose.keys.cosekey import CoseKey, KTY, EllipticCurveTypes


@CoseKey.record_kty(KTY.EC2)
@dataclass(init=False)
class EC2(CoseKey):
    _crv: Optional[EllipticCurveTypes] = None
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
                 kid: Optional[bytes] = None,
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
    def crv(self) -> Optional[EllipticCurveTypes]:
        return self._crv

    @crv.setter
    def crv(self, new_crv: Optional[EllipticCurveTypes]) -> None:
        if new_crv is not None:
            _ = EllipticCurveTypes(new_crv)
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
                    v = EllipticCurveTypes(v)
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
        kws = ['_' + kw for kw in argv if self.EC2Prm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.EC2Prm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(EC2)>']
        output.extend(
            self._base_repr(k, v) if k not in [-2, -3, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)
