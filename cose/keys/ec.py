from binascii import hexlify
from enum import IntEnum
from typing import Optional, Tuple

import dataclasses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from dataclasses import dataclass
from ecdsa import SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point

from cose.attributes.algorithms import CoseAlgorithms, config, CoseEllipticCurves
from cose.attributes.context import CoseKDFContext
from cose.exceptions import CoseInvalidAlgorithm
from cose.keys.cosekey import CoseKey, KTY, KeyOps


@CoseKey.record_kty(KTY.EC2)
@dataclass(init=False)
class EC2(CoseKey):
    _crv: Optional[CoseEllipticCurves] = None
    _x: Optional[bytes] = None
    _y: Optional[bytes] = None
    _d: Optional[bytes] = None

    class EC2Prm(IntEnum):
        """ EC2 COSE key parameters. """
        CRV = -1
        X = -2
        Y = -3
        D = -4

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> 'EC2':
        """
        Returns an initialized COSE Key object of type EC2.

        :param cose_key_obj: Dict containing integer representations of COSE Key parameters and there values.
        :return: an initialized EC2 key
        """

        cose_key = cls(
            kid=cose_key_obj.get(cls.Common.KID),
            alg=cose_key_obj.get(cls.Common.ALG),
            key_ops=cose_key_obj.get(cls.Common.KEY_OPS),
            base_iv=cose_key_obj.get(cls.Common.BASE_IV),
            crv=cose_key_obj.get(cls.EC2Prm.CRV),
            x=cose_key_obj.get(cls.EC2Prm.X),
            y=cose_key_obj.get(cls.EC2Prm.Y),
            d=cose_key_obj.get(cls.EC2Prm.D)
        )

        return cose_key

    def __init__(self,
                 kid: Optional[bytes] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 crv: Optional[CoseEllipticCurves] = None,
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
            self._crv = CoseEllipticCurves(new_crv)
        else:
            self._crv = None

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

    def encode(self, *argv):
        """ Encodes specified attributes of the COSE Key object as a dictionary. """
        kws = []

        for kw in argv:
            if kw.upper() in self.EC2Prm.__members__:
                kws.append('_' + kw)

        return {**super().encode(*argv), **{self.EC2Prm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def ecdh_key_derivation(self,
                            public_key: 'EC2',
                            context: CoseKDFContext,
                            alg: Optional[CoseAlgorithms] = None,
                            curve: Optional[CoseEllipticCurves] = None) -> Tuple[bytes, bytes]:
        """
        Derives a CEK with ECDH + HKDF algorithm. The parameter 'alg' and 'curve' parameters are optional in case they
        are already provided by one of the COSE key objects.

        :param public_key: an EC2 key containing public key bytes.
        :param context: a CoseKDFContext for the HKDF algorithm.
        :param alg: an optional algorithm parameter (specifies the exact algorithm used for the key derivation).
        :param curve: an optional curve
        """

        self._check_key_conf(alg, KeyOps.DERIVE_KEY, public_key, curve)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        try:
            crv_cfg = config(CoseEllipticCurves(self.crv))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        d = ec.derive_private_key(int(hexlify(self.d), 16), crv_cfg.curve[1](), default_backend())
        p = ec.EllipticCurvePublicNumbers(int(hexlify(public_key.x), 16), int(hexlify(public_key.y), 16),
                                          crv_cfg.curve[1]())
        p = p.public_key(default_backend())

        shared_key = d.exchange(ECDH(), p)

        derived_key = alg_cfg.kdf(algorithm=alg_cfg.hash(),
                                  length=int(context.supp_pub_info.key_data_length / 8),
                                  salt=None,
                                  info=context.encode(),
                                  backend=default_backend()).derive(shared_key)

        return shared_key, derived_key

    def sign(self,
             to_be_signed: bytes,
             alg: Optional[CoseAlgorithms] = None,
             curve: CoseEllipticCurves = None) -> bytes:
        """
        Computes a digital signature over 'to_be_signed'. The parameter 'alg' and 'curve' parameters are optional in
        case they are already provided by one of the COSE key objects.

        :param to_be_signed: data over which the signature is calculated
        :param alg: an optional algorithm parameter (specifies the exact algorithm used for the signature).
        :param curve: an optional curve
        """

        self._check_key_conf(algorithm=alg, key_operation=KeyOps.SIGN, curve=curve)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        sk = SigningKey.from_secret_exponent(int(hexlify(self.d), 16), curve=alg_cfg.curve)

        return sk.sign_deterministic(to_be_signed, hashfunc=alg_cfg.hash)

    def verify(self,
               to_be_signed: bytes,
               signature: bytes,
               alg: Optional[CoseAlgorithms] = None,
               curve: Optional[CoseEllipticCurves] = None) -> bool:
        """
        Verifies the digital signature over 'to_be_signed'. The parameter 'alg' and 'curve' parameters are optional in
        case they are already provided by one of the COSE key objects.

        :param to_be_signed: data that was signed
        :param signature: signature to verify
        :param alg: an optional algorithm parameter (specifies the exact algorithm used for the signature).
        :param curve: an optional curve
        """

        self._check_key_conf(algorithm=alg, key_operation=KeyOps.VERIFY, curve=curve)

        try:
            alg_cfg = config(CoseAlgorithms(self.alg))
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        p = Point(curve=alg_cfg.curve.curve, x=int(hexlify(self.x), 16), y=int(hexlify(self.y), 16))
        vk = VerifyingKey.from_public_point(p, alg_cfg.curve, alg_cfg.hash, validate_point=True)

        return vk.verify(signature, to_be_signed)

    def __repr__(self):
        hdr = '<COSE_Key(EC2): {'
        output = [f'{k[1:]}: {v.__repr__()}' for k, v in dataclasses.asdict(self).items() if v is not None]
        return hdr + ", ".join(output)[2:] + '}>'
