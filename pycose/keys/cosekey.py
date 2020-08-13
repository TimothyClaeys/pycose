import base64
from abc import ABCMeta, abstractmethod
from binascii import hexlify
from enum import IntEnum, unique
from typing import List, Union, Dict, Optional

import dataclasses as dc

from pycose.algorithms import AlgorithmIDs


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
class EllipticCurveTypes(IntEnum):
    RESERVED = 0
    P_256 = 1
    P_384 = 2
    P_521 = 3
    X25519 = 4
    X448 = 5
    ED25519 = 6
    ED448 = 7
    SECP256K1 = 8


@dc.dataclass
class CoseKey(metaclass=ABCMeta):
    _kty: Optional[KTY]
    _kid: Optional[Union[int, bytes]]
    _alg: Optional[AlgorithmIDs]
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
                raise ValueError("Can only decorate subclass of CoseKey")
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
                    v = AlgorithmIDs(v)
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
    def alg(self) -> Optional[AlgorithmIDs]:
        return self._alg

    @alg.setter
    def alg(self, new_alg: AlgorithmIDs) -> None:
        if new_alg is not None:
            _ = AlgorithmIDs(new_alg)  # check if the new value is a known COSE Algorithm
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


class CoseKeySet:
    def __init__(self, cose_keys: List[CoseKey] = None):
        if cose_keys is None:
            self.cose_keys = []
        else:
            self.cose_keys = cose_keys
