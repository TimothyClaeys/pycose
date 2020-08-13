from enum import IntEnum
from typing import Optional

import dataclasses
from dataclasses import dataclass

from pycose.keys.cosekey import CoseKey, KTY, CoseEllipticCurves, EllipticCurveKeys


@CoseKey.record_kty(KTY.OKP)
@dataclass(init=False)
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
                 kid: Optional[ bytes] = None,
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
        kws = [kw for kw in argv if self.OKPPrm.has_member(kw.upper())]
        return {**super().encode(*argv), **{self.OKPPrm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(OKP)>']
        output.extend(self._base_repr(k, v) if k not in [-2, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)
