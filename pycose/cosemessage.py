import abc
from typing import Type, Optional

import cbor2

from pycose.basicstructure import BasicCoseStructure
from pycose.cosekey import CoseKey


class CoseMessage(BasicCoseStructure, metaclass=abc.ABCMeta):
    """ Parent class of all COSE message types. """

    COSE_MSG_ID = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag: int):
        """Decorator to record all the CBOR tags dynamically"""

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls.COSE_MSG_ID[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls, received: bytes):
        """Decode received COSE message based on the CBOR tag."""

        try:
            cbor_tag = cbor2.loads(received).tag
            cose_obj = cbor2.loads(received).value
        except AttributeError:
            raise AttributeError("Message was not tagged.")
        except ValueError:
            raise ValueError("Decode accepts only bytes as input.")

        if isinstance(cose_obj, list):
            try:
                return cls.COSE_MSG_ID[cbor_tag].from_cose_obj(cose_obj)
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)
        else:
            raise TypeError("Message is not a COSE security message")

    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        """Returns an initialized COSE message object."""
        msg = super().from_cose_obj(cose_obj)
        msg.payload = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict],
                 uhdr: Optional[dict],
                 payload: bytes,
                 external_aad: bytes,
                 key: Optional[Type[CoseKey]]):
        super().__init__(phdr, uhdr)
        self.payload = payload
        self.external_aad = external_aad
        self.key = key

    @property
    def external_aad(self) -> bytes:
        return self._external_aad

    @external_aad.setter
    def external_aad(self, new_external_aad: bytes) -> None:
        if type(new_external_aad) is not bytes:
            raise TypeError("external_aad must be of type 'bytes'")
        self._external_aad = new_external_aad

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, new_payload: bytes) -> None:
        if type(new_payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = new_payload  # can be plaintext or ciphertext

    @property
    def key(self) -> Optional[Type[CoseKey]]:
        return self._key

    @key.setter
    def key(self, new_key: Optional[Type[CoseKey]]) -> None:
        if not issubclass(type(new_key), CoseKey) and new_key is not None:
            raise TypeError("key must be of type 'bytes'")
        self._key = new_key

    def _base_structure(self, structure: list) -> list:
        if len(self.phdr) == 0:
            structure.append(b'')
        else:
            structure.append(self.encode_phdr())

        structure.append(self._external_aad)

        return structure

    @abc.abstractmethod
    def encode(self, tagged: bool = True) -> bytes:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def context(self) -> str:
        """Getter for the context of the message."""
        raise NotImplementedError
