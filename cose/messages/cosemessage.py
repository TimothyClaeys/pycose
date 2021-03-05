import abc
from typing import Optional, TypeVar, TYPE_CHECKING

import cbor2

from cose.keys.symmetric import SymmetricKey
from cose.keys.okp import OKPKey
from cose.keys.ec2 import EC2Key
from cose.messages.cosebase import CoseBase
from cose.exceptions import CoseException

if TYPE_CHECKING:
    from cose.keys.cosekey import CK

CBOR = bytes


class CoseMessage(CoseBase, metaclass=abc.ABCMeta):
    """ Parent class of all COSE message types. """

    # private dictionary to record all COSE message types dynamically
    _COSE_MSG_ID = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag: int):
        """ Decorator to record all the CBOR tags dynamically. """

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls._COSE_MSG_ID[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls, received: bytes) -> 'CM':
        """
        Decode received COSE message based on the CBOR tag.

        :param received: COSE messages encoded as bytes
        :raises AttributeError: When the COSE message, it cannot be decoded properly
        :raises ValueError: The received parameter must be bytes
        :raises KeyError: thrown when the CBOR tag, identifying the COSE message is unrecognized
        :raises TypeError: thrown when the messages cannot be decoded properly
        :returns: An initialized CoseMessage
        """

        try:
            cbor_tag = cbor2.loads(received).tag
            cose_obj = cbor2.loads(received).value
        except AttributeError:
            raise AttributeError("Message was not tagged.")
        except ValueError:
            raise ValueError("Decode accepts only bytes as input.")

        if isinstance(cose_obj, list):
            try:
                return cls._COSE_MSG_ID[cbor_tag].from_cose_obj(cose_obj)
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)
        else:
            raise TypeError("Message is not a COSE security message")

    @classmethod
    def from_cose_obj(cls, cose_obj: list, *args, **kwargs):
        """ Returns an initialized COSE message object. """

        msg = super().from_cose_obj(cose_obj)
        msg.payload = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['CK'] = None):

        super().__init__(phdr, uhdr)

        self.payload = payload
        self.external_aad = external_aad
        self.key = key

    @property
    def external_aad(self) -> bytes:
        return self._external_aad

    @property
    @abc.abstractmethod
    def cbor_tag(self):
        raise NotImplementedError()

    @external_aad.setter
    def external_aad(self, new_external_aad: bytes) -> None:
        if type(new_external_aad) is not bytes:
            raise TypeError("external_aad must be of type 'bytes'")
        self._external_aad = new_external_aad

    @property
    def key(self) -> 'CK':
        return self._key

    @key.setter
    def key(self, key: Optional['CK']):
        if isinstance(key, SymmetricKey):
            if key.k == b'':
                raise CoseException("Key does not contain secret bytes")
            self._key = key
        elif isinstance(key, EC2Key):
            if key.d == b'' and key.x == b'' and key.y == b'':
                raise CoseException("Key does not contain private bytes or public bytes")
            self._key = key
        elif isinstance(key, OKPKey):
            if key.d == b'' and key.x == b'':
                raise CoseException("Key does not contain private bytes or public bytes")
            self._key = key
        elif key is None:
            self._key = key
        else:
            raise CoseException("Invalid COSE key")

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, new_payload: bytes) -> None:
        if type(new_payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = new_payload  # can be plaintext or ciphertext

    @abc.abstractmethod
    def encode(self, message: list, tag: bool = True, *args, **kwargs) -> CBOR:
        if tag:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return message

    def _base_structure(self, structure: list) -> list:
        if len(self.phdr) == 0:
            structure.append(b'')
        else:
            structure.append(self.phdr_encoded)

        structure.append(self._external_aad)

        return structure


CM = TypeVar('CM', bound=CoseMessage)
