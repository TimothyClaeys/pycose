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
from pycose.exceptions import CoseIllegalKeyOps, CoseIllegalCurve
from pycose.keys.cosekey import CoseKey, KTY, EllipticCurveTypes, KeyOps


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

    KEY_DERIVATION_CURVES = {
        EllipticCurveTypes.P_256: SECP256R1,
        EllipticCurveTypes.P_384: SECP384R1,
        EllipticCurveTypes.P_521: SECP521R1,
    }

    def __init__(self,
                 kid: Optional[bytes] = None,
                 alg: Optional[int] = None,
                 key_ops: Optional[int] = None,
                 base_iv: Optional[bytes] = None,
                 crv: Optional[EllipticCurveTypes] = None,
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

    def ecdh_key_derivation(self,
                            public_key: 'EC2',
                            context: CoseKDFContext,
                            alg: Optional[AlgorithmIDs] = None,
                            curve: Optional[EllipticCurveTypes] = None) -> Tuple[bytes, bytes]:
        """ Derive a CEK from ECDH + HKDF algorithm """

        self._check_key_conf(alg, KeyOps.DERIVE_KEY, curve)

        algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value

        try:
            curve = self.KEY_DERIVATION_CURVES[self.crv]()
        except KeyError:
            raise CoseIllegalCurve

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

    def compute_signature(self,
                          to_be_signed: bytes,
                          alg: Optional[AlgorithmIDs] = None,
                          curve: EllipticCurveTypes = None) -> bytes:

        self._check_key_conf(alg, KeyOps.SIGN, curve)

        algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
        sk = SigningKey.from_secret_exponent(int(hexlify(self.d), 16), curve=algorithm.curve)

        return sk.sign_deterministic(to_be_signed, hashfunc=algorithm.hash)

    def verify_signature(self,
                         to_be_signed: bytes,
                         signature: bytes,
                         alg: Optional[AlgorithmIDs] = None,
                         curve: Optional[EllipticCurveTypes] = None) -> bool:
        self._check_key_conf(alg, KeyOps.SIGN, curve)

        algorithm: AlgoParam = AlgID2Crypto[self.alg.name].value
        p = Point(curve=algorithm.curve, x=int(hexlify(self.x), 16), y=int(hexlify(self.y), 16))
        vk = VerifyingKey.from_public_point(p, algorithm.curve, algorithm.hash, validate_point=True)

        return vk.verify(signature, to_be_signed)

    def _check_key_conf(self, algorithm: AlgorithmIDs, key_operation: KeyOps, curve: EllipticCurveTypes):
        """ Helper function that checks the configuration of the COSE key object. """

        if self.alg is not None and algorithm is not None and self.alg != algorithm:
            raise ValueError("COSE key algorithm does not match with parameter 'algorithm'.")

        if algorithm is not None:
            self.alg = algorithm

        if self.crv is not None and curve is not None and self.crv != curve:
            raise ValueError("Curve in COSE key clashes with parameter 'curve'.")

        if curve is not None:
            self.crv = curve

        if self.key_ops is not None and key_operation is not None and self.key_ops != key_operation:
            raise CoseIllegalKeyOps(f"COSE key operation does not match with {key_operation}")

        if key_operation is not None:
            self.key_ops = key_operation
