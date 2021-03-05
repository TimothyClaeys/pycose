import base64
from abc import ABC, abstractmethod
from collections.abc import MutableMapping
from typing import Optional, TypeVar, Type, List, Any, TYPE_CHECKING

import cbor2

from cose.algorithms import CoseAlgorithm
from cose.exceptions import CoseException
from cose.headers import EphemeralKey, StaticKey
from cose.keys.keyops import KeyOps
from cose.keys.keyparam import KpKty, KpKeyOps, KpAlg, KpKid, KpBaseIV, KeyParam

# noinspection PyUnresolvedReferences
from cose.keys.keytype import KTY

if TYPE_CHECKING:
    from cose.headers import CoseHeaderAttribute
    from cose.algorithms import CoseAlg
    from cose.keys.keytype import KTYPE
    from cose.keys.keyops import KEYOPS


class CoseKey(MutableMapping, ABC):
    """ Abstract base class for all key type in COSE. """

    _key_types = {}

    @classmethod
    def decode(cls, received: bytes):
        return CoseKey.from_dict(cbor2.loads(received))

    @classmethod
    def record_kty(cls, kty: Type['KTYPE']):
        """
        Decorator to record all the COSE key types dynamically.

        :param kty: Integer identifying the COSE key type (see RFC 8152)
        :return: A Decorator function.
        """

        def decorator(the_class: Type['CK']) -> Type['CK']:
            if not issubclass(the_class, CoseKey):
                raise ValueError("Can only decorate subclass of CoseKey")
            cls._key_types[kty.identifier] = the_class
            cls._key_types[kty.fullname] = the_class
            cls._key_types[kty] = the_class
            return the_class

        return decorator

    @classmethod
    def from_dict(cls, received: dict) -> 'CK':
        """
        Decoding function for COSE key objects.

        :param received: Dictionary must contain the element otherwise the key object cannot be decoded properly.
        :return: A COSE Key object.
        """

        if KpKty in received:
            r = received[KpKty]
            key_obj = cls._key_types[r].from_dict(received)
        elif KpKty.identifier in received:
            key_obj = cls._key_types[received[KpKty.identifier]].from_dict(received)
        elif KpKty.fullname in received:
            key_obj = cls._key_types[received[KpKty.fullname]].from_dict(received)
        else:
            raise CoseException("Could not decode CoseKey type")

        return key_obj

    @staticmethod
    def base64decode(to_decode: str) -> bytes:
        """
        Decodes BASE64 encoded keys to bytes.

        :param to_decode: BASE64 encoded key.
        :return: Key as bytes.
        """

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

    @staticmethod
    def base64encode(to_encode: bytes) -> str:
        """
        Encodes key bytes as a string.

        :param to_encode: Bytes to encode.
        :return: BASE64 encoding.
        """

        return base64.b64encode(to_encode).decode("utf-8")

    def __init__(self, key_dict: dict):
        self.store = dict()
        self.store.update(key_dict)

        self.store.setdefault(KpKeyOps, [])

    def verify(self, key_type: Type['CK'], algorithm: Type['CoseAlg'], key_ops: List[Type['KEYOPS']]):
        """ Verify attributes of the COSE_key object."""

        if not isinstance(self, key_type):
            raise CoseException("Wrong key type")

        if self.alg is not None and self.alg.identifier != algorithm.identifier:
            raise CoseException("Conflicting algorithms in key and COSE headers")

        if len(self.key_ops):
            match_key_ops = False

            for k in key_ops:
                if k in self.key_ops:
                    match_key_ops = True

            if not match_key_ops:
                raise CoseException("Wrong key operations specified")

    def __getitem__(self, key):
        return self.store[self._key_transform(key)]

    def __setitem__(self, key, value):
        self.store[self._key_transform(key)] = value

    def __delitem__(self, key):
        del self.store[self._key_transform(key)]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    @property
    def kty(self) -> Optional[Type['KTYPE']]:
        return self.store.get(KpKty)

    @kty.setter
    def kty(self, kty: Any):
        self.store[KpKty] = KpKty.from_id(kty)

    @property
    def alg(self) -> Optional[Type['CoseAlg']]:
        return self.store.get(KpAlg)

    @alg.setter
    def alg(self, alg: Type['CoseAlg']):
        self.store[KpAlg] = CoseAlgorithm.from_id(alg)

    @property
    def kid(self) -> bytes:
        return self.store.get(KpKid, b'')

    @kid.setter
    def kid(self, kid: bytes):
        if type(kid) is not bytes:
            raise TypeError(f"kid must be of type 'bytes'")
        self.store[KpKid] = kid

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        return self.store.get(KpKeyOps)

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Type['KEYOPS']]):
        if new_key_ops is None:
            self.store[KpKeyOps] = []
        elif isinstance(new_key_ops, list):
            self.store[KpKeyOps] = [KeyOps.from_id(k) for k in new_key_ops]
        else:
            raise ValueError("Key operations should be a list with KeyOps values.")

    @property
    def base_iv(self) -> bytes:
        return self.store.get(KpBaseIV, b'')

    @base_iv.setter
    def base_iv(self, base_iv: bytes):
        if type(base_iv) is not bytes:
            raise TypeError(f"base_iv must be of type 'bytes'")
        self.store[KpBaseIV] = base_iv

    def encode(self):
        return cbor2.dumps(self.store, default=self._custom_cbor_encoder)

    @property
    @abstractmethod
    def is_valid_key(self):
        raise NotImplementedError()

    @classmethod
    def _custom_cbor_encoder(cls, encoder, cose_attribute: 'CoseHeaderAttribute'):
        encoder.encode(cose_attribute.identifier)

    @staticmethod
    def _key_transform(key):
        try:
            return KeyParam.from_id(key.identifier)
        except KeyError:
            return key

    def _key_repr(self) -> dict:
        names = {kp.__name__: self.store[kp].__name__ if hasattr(self.store[kp], '__name__') else self.store[kp] for kp
                 in sorted(self.store, key=lambda item: item.identifier)}

        if KpKeyOps.__name__ in names:
            names[KpKeyOps.__name__] = [ops.__name__ if hasattr(ops, '__name__') else ops for ops in
                                        names[KpKeyOps.__name__]]

        return names


EphemeralKey.value_parser = CoseKey.from_dict
StaticKey.value_parser = CoseKey.from_dict

CK = TypeVar('CK', bound=CoseKey)
