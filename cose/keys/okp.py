from enum import IntEnum
from typing import Optional, Tuple

import dataclasses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from dataclasses import dataclass

from cose.attributes.algorithms import CoseAlgorithms, config, CoseEllipticCurves
from cose.attributes.context import CoseKDFContext
from cose.exceptions import CoseInvalidAlgorithm
from cose.keys.cosekey import CoseKey, KTY, KeyOps


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
    def from_cose_key_obj(cls, cose_key_obj: dict) -> 'OKP':
        """ Returns an initialized COSE_Key object of type OKP."""

        cose_key = cls(
            kid=cose_key_obj.get(cls.Common.KID),
            alg=cose_key_obj.get(cls.Common.ALG),
            key_ops=cose_key_obj.get(cls.Common.KEY_OPS),
            base_iv=cose_key_obj.get(cls.Common.BASE_IV),
            crv=cose_key_obj.get(cls.OKPPrm.CRV),
            x=cose_key_obj.get(cls.OKPPrm.X),
            d=cose_key_obj.get(cls.OKPPrm.D)
        )

        return cose_key

    def __init__(self,
                 kid: Optional[bytes] = None,
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
            self._crv = CoseEllipticCurves(new_crv)
        else:
            self._crv = None

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

    def encode(self, *argv):
        kws = []

        for kw in argv:
            if kw.upper() in self.OKPPrm.__members__:
                kws.append('_' + kw)

        return {**super().encode(*argv), **{self.OKPPrm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def x25519_key_derivation(self,
                              public_key: 'OKP',
                              context: CoseKDFContext = b'',
                              alg: Optional[CoseAlgorithms] = None,
                              curve: Optional[CoseEllipticCurves] = None) -> Tuple[bytes, bytes]:

        self._check_key_conf(alg, KeyOps.DERIVE_KEY, public_key, curve)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        p = X25519PublicKey.from_public_bytes(public_key.x)
        d = X25519PrivateKey.from_private_bytes(self.d)

        shared_secret = d.exchange(p)

        derived_key = alg_cfg.kdf(algorithm=alg_cfg.hash(),
                                  length=int(context.supp_pub_info.key_data_length / 8),
                                  salt=None,
                                  info=context.encode(),
                                  backend=default_backend()).derive(shared_secret)

        return shared_secret, derived_key

    def __repr__(self):
        hdr = '<COSE_Key(OKP): {'
        output = [f'{k[1:]}: {v.__repr__()}' for k, v in dataclasses.asdict(self).items() if v is not None]
        return hdr + ", ".join(output)[2:] + '}>'
