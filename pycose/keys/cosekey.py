import base64
from abc import ABC
from collections.abc import MutableMapping
from typing import Optional, TypeVar, Type, List, Any, TYPE_CHECKING, Callable, Set

import cbor2

from pycose import utils
from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseException, CoseIllegalKeyType, CoseIllegalAlgorithm, CoseIllegalKeyOps
from pycose.headers import EphemeralKey, StaticKey
from pycose.keys.keyops import KeyOps
from pycose.keys.keyparam import KpKty, KpKeyOps, KpAlg, KpKid, KpBaseIV, KeyParam

if TYPE_CHECKING:
    from pycose.headers import CoseHeaderAttribute
    from pycose.algorithms import CoseAlg
    from pycose.keys.keytype import KTYPE
    from pycose.keys.keyops import KEYOPS
    from pycose.keys.keyparam import KP


class CoseKey(MutableMapping, ABC):
    """ Abstract base class for all COSE key types. """

    _key_types = {}

    @classmethod
    def decode(cls, received: bytes) -> 'CK':
        """
        Decodes a CBOR-encoded COSE key object.

        :param received: A CBOR-encoded bytestring.
        :return: An initialized COSE key.
        """

        return CoseKey.from_dict(cbor2.loads(received))

    @classmethod
    def record_kty(cls, kty: Type['KTYPE']) -> Callable:
        """
        Decorator to record all the COSE key types dynamically.

        :param kty: A :class:`pycose.keys.keytype.KTY`
        :return: A decorator function.
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
    def _extract_from_dict(cls, cose_key: dict, parameter: Type['KP'], default=b''):
        if parameter in cose_key:
            v = cose_key[parameter]
        elif parameter.identifier in cose_key:
            v = cose_key[parameter.identifier]
        elif parameter.fullname in cose_key:
            v = cose_key[parameter.fullname]
        else:
            v = default

        return v

    @classmethod
    def _remove_from_dict(cls, cose_key: dict, parameter: Type['KP']):
        cose_key.pop(parameter, None)
        cose_key.pop(parameter.identifier, None)
        cose_key.pop(parameter.fullname, None)

    @classmethod
    def from_dict(cls, received: dict) -> 'CK':
        """
        Initialize a COSE key from a dictionary.

        :param received: Dictionary to translate to COSE key.
        :return: An initialized COSE Key object.
        """

        if KpKty in received:
            key_obj = cls._key_types[received[KpKty]].from_dict(received)
        elif KpKty.identifier in received:
            key_obj = cls._key_types[received[KpKty.identifier]].from_dict(received)
        elif KpKty.fullname in received:
            key_obj = cls._key_types[received[KpKty.fullname]].from_dict(received)
        else:
            raise CoseIllegalKeyType("Could not decode CoseKey type, KpKty not set or unknown.")

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

        if KpKeyOps in key_dict and len(key_dict[KpKeyOps]) == 0:
            del key_dict[KpKeyOps]

        self.store.update(key_dict)

    def verify(self, key_type: Type['CK'], algorithm: Type['CoseAlg'], key_ops: List[Type['KEYOPS']]):
        """ Verify attributes of the COSE_key object."""

        if not isinstance(self, key_type):
            raise CoseException("Wrong key type")

        if self.alg is not None and self.alg.identifier != algorithm.identifier:
            raise CoseIllegalAlgorithm("Conflicting algorithms in key and COSE headers")

        if len(self.key_ops):
            match_key_ops = False

            for k in key_ops:
                if k in self.key_ops:
                    match_key_ops = True

            if not match_key_ops:
                raise CoseIllegalKeyOps(f"Illegal key operations specified. Allowed: {key_ops}, found: {self.key_ops}")

    def __getitem__(self, key):
        return self.store[self._key_transform(key, allow_unknown_attrs=True)]

    def __setitem__(self, key, value):
        self.store[self._key_transform(key, allow_unknown_attrs=True)] = value

    def __delitem__(self, key):
        del self.store[self._key_transform(key, allow_unknown_attrs=True)]

    def __contains__(self, item):
        return self.store.__contains__(self._key_transform(item, allow_unknown_attrs=True))

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    @property
    def kty(self) -> Optional[Type['KTYPE']]:
        """ Returns the value of the mandatory :class:`~pycose.keys.keyparam.KpKty` key parameter """

        return self.store.get(KpKty)

    @kty.setter
    def kty(self, kty: Any):
        self.store[KpKty] = KpKty.from_id(kty)

    @property
    def alg(self) -> Optional[Type['CoseAlg']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpAlg` key parameter """

        return self.store.get(KpAlg)

    @alg.setter
    def alg(self, alg: Type['CoseAlg']) -> None:
        self.store[KpAlg] = CoseAlgorithm.from_id(alg)

    @property
    def kid(self) -> bytes:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKid` key parameter """

        return self.store.get(KpKid, b'')

    @kid.setter
    def kid(self, kid: bytes) -> None:
        if type(kid) is not bytes:
            raise TypeError(f"kid must be of type 'bytes'")
        self.store[KpKid] = kid

    @property
    def key_ops(self) -> List[Type['KEYOPS']]:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpKeyOps` key parameter """

        return self.store.get(KpKeyOps, [])

    @key_ops.setter
    def key_ops(self, new_key_ops: List[Type['KEYOPS']]) -> None:
        if isinstance(new_key_ops, list):
            self.store[KpKeyOps] = [KeyOps.from_id(k) for k in new_key_ops]
        else:
            raise ValueError("Key operations should be a list with KeyOps values.")

    @property
    def base_iv(self) -> bytes:
        """ Returns the value of the :class:`~pycose.keys.keyparam.KpBaseIV` key parameter """

        return self.store.get(KpBaseIV, b'')

    @base_iv.setter
    def base_iv(self, base_iv: bytes) -> None:
        if type(base_iv) is not bytes:
            raise TypeError(f"base_iv must be of type 'bytes'")
        self.store[KpBaseIV] = base_iv

    def encode(self) -> bytes:
        """
        Encodes the COSE key as a CBOR map

        :return: A COSE key encoded as CBOR map
        """
        return cbor2.dumps(self.store, default=self._custom_cbor_encoder)

    @classmethod
    def _custom_cbor_encoder(cls, encoder, cose_attribute: 'CoseHeaderAttribute'):
        encoder.encode(cose_attribute.identifier)

    @staticmethod
    def _key_transform(key, allow_unknown_attrs=False):
        return KeyParam.from_id(key, allow_unknown_attrs)

    @classmethod
    def _supported_by_key_type(cls, attribute, supported: Set[Any]):
        return attribute in supported \
               or attribute in map(lambda x: getattr(x, 'identifier'), supported) \
               or attribute in map(lambda x: getattr(x, 'fullname'), supported)

    def _key_repr(self) -> dict:
        names = {
            kp.__name__ if hasattr(kp, '__name__') else kp:
                self.store[kp].__name__ if hasattr(self.store[kp], '__name__') else self.store[kp] for kp
            in sorted(self.store, key=lambda item: item.identifier if hasattr(item, 'identifier') else 65536)}

        if KpKeyOps.__name__ in names:
            names[KpKeyOps.__name__] = [ops.__name__ if hasattr(ops, '__name__') else ops for ops in
                                        names[KpKeyOps.__name__]]

        if 'BASE_IV' in names and len(names['BASE_IV']) > 0:
            names['BASE_IV'] = utils.truncate(names['BASE_IV'])

        return names


EphemeralKey.value_parser = CoseKey.from_dict
StaticKey.value_parser = CoseKey.from_dict

CK = TypeVar('CK', bound=CoseKey)
