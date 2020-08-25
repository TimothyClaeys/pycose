from binascii import hexlify
from enum import IntEnum
from typing import Optional, Tuple

import dataclasses
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, ECDH
from dataclasses import dataclass
from ecdsa import SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point

from pycose.algorithms import AlgorithmIDs, AlgoParam, AlgID2Crypto
from pycose.context import CoseKDFContext
from pycose.exceptions import CoseIllegalCurve, CoseInvalidAlgorithm
from pycose.keys.cosekey import CoseKey, KTY, EllipticCurveType, KeyOps


@CoseKey.record_kty(KTY.EC2)
@dataclass(init=False)
class EC2(CoseKey):
    _crv: Optional[EllipticCurveType] = None
    _x: Optional[bytes] = None
    _y: Optional[bytes] = None
    _d: Optional[bytes] = None

    class EC2Prm(IntEnum):
        CRV = -1
        X = -2
        Y = -3
        D = -4

    KEY_DERIVATION_CURVES = {
        EllipticCurveType.P_256: SECP256R1,
        EllipticCurveType.P_384: SECP384R1,
        EllipticCurveType.P_521: SECP521R1,
    }

    @classmethod
    def from_cose_key_obj(cls, cose_key_obj: dict) -> 'EC2':
        """ Returns an initialized COSE_Key object of type EC2."""

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
                 crv: Optional[EllipticCurveType] = None,
                 x: Optional[bytes] = None,
                 y: Optional[bytes] = None,
                 d: Optional[bytes] = None):
        super().__init__(KTY.EC2, kid, alg, key_ops, base_iv)
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d

    @property
    def crv(self) -> Optional[EllipticCurveType]:
        return self._crv

    @crv.setter
    def crv(self, new_crv: Optional[EllipticCurveType]) -> None:
        if new_crv is not None:
            _ = EllipticCurveType(new_crv)
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

    def encode(self, *argv):
        kws = []

        for kw in argv:
            if kw.upper() in self.EC2Prm.__members__:
                kws.append('_' + kw)

        return {**super().encode(*argv), **{self.EC2Prm[kw[1:].upper()]: dataclasses.asdict(self)[kw] for kw in kws}}

    def __repr__(self):
        content = self.encode()
        output = ['<COSE_Key(EC2)>']
        output.extend(
            self._base_repr(k, v) if k not in [-2, -3, -4] else self._key_repr(k, v) for k, v in content.items())
        return "\n".join(output)

    def ecdh_key_derivation(self,
                            public_key: 'EC2',
                            context: CoseKDFContext,
                            alg: Optional[AlgorithmIDs] = None,
                            curve: Optional[EllipticCurveType] = None) -> Tuple[bytes, bytes]:
        """ Derive a CEK with ECDH + HKDF algorithm """

        self._check_key_conf(alg, KeyOps.DERIVE_KEY, public_key, curve)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        try:
            curve = self.KEY_DERIVATION_CURVES[self.crv]()
        except KeyError:
            raise CoseIllegalCurve(curve)

        d = ec.derive_private_key(int(hexlify(self.d), 16), curve, openssl.backend)
        p = ec.EllipticCurvePublicNumbers(int(hexlify(public_key.x), 16), int(hexlify(public_key.y), 16), curve)
        p = p.public_key(openssl.backend)

        shared_key = d.exchange(ECDH(), p)

        derived_key = algorithm.key_derivation(algorithm=algorithm.hash(),
                                               length=int(context.supp_pub_info.key_data_length / 8),
                                               salt=None,
                                               info=context.encode(),
                                               backend=openssl.backend).derive(shared_key)

        return shared_key, derived_key

    def sign(self,
             to_be_signed: bytes,
             alg: Optional[AlgorithmIDs] = None,
             curve: EllipticCurveType = None) -> bytes:
        """ Sign a message """

        self._check_key_conf(algorithm=alg, key_operation=KeyOps.SIGN, curve=curve)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        sk = SigningKey.from_secret_exponent(int(hexlify(self.d), 16), curve=algorithm.curve)

        return sk.sign_deterministic(to_be_signed, hashfunc=algorithm.hash)

    def verify(self,
               to_be_signed: bytes,
               signature: bytes,
               alg: Optional[AlgorithmIDs] = None,
               curve: Optional[EllipticCurveType] = None) -> bool:
        """ Verify a message's signature """

        self._check_key_conf(algorithm=alg, key_operation=KeyOps.VERIFY, curve=curve)

        try:
            alg = self.alg.name if hasattr(self.alg, "name") else AlgorithmIDs(self.alg).name

            algorithm: AlgoParam = AlgID2Crypto[alg].value
        except KeyError as err:
            raise CoseInvalidAlgorithm(err)

        p = Point(curve=algorithm.curve.curve, x=int(hexlify(self.x), 16), y=int(hexlify(self.y), 16))
        vk = VerifyingKey.from_public_point(p, algorithm.curve, algorithm.hash, validate_point=True)

        return vk.verify(signature, to_be_signed)
