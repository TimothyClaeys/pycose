import abc
from typing import Type, Union, Optional

import cbor2

from pycose.basicstructure import BasicCoseStructure
from pycose.cosekey import CoseKey


class CoseMessage(BasicCoseStructure, metaclass=abc.ABCMeta):
    """ Parent class of all COSE message types. """

    cose_msg_id = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag: int):
        """Decorator to record all the CBOR tags dynamically"""

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls.cose_msg_id[cbor_tag] = the_class
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
                return cls.cose_msg_id[cbor_tag].from_cose_obj(cose_obj)
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)
        else:
            raise TypeError("Message is not a COSE security message")

    @classmethod
    def from_cose_obj(cls, cose_obj: list):
        """Returns an initialized COSE message object."""

        try:
            phdr = BasicCoseStructure.parse_cose_hdr(cbor2.loads(cose_obj.pop(0)))
        except (ValueError, EOFError):
            phdr = {}

        try:
            uhdr = BasicCoseStructure.parse_cose_hdr(cose_obj.pop(0))
        except ValueError:
            uhdr = {}

        payload = cose_obj.pop(0)

        return cls(phdr, uhdr, payload)

    def __init__(self, phdr: dict, uhdr: dict, payload: bytes, external_aad: bytes, key: Optional[Type[CoseKey]]):
        super(CoseMessage, self).__init__(phdr, uhdr, payload)
        self.external_aad = external_aad
        self.key = key

    @abc.abstractmethod
    def encode(self, tagged: bool = True):
        raise NotImplementedError("Cannot not instantiate abstract class CoseMessage")

    @property
    @abc.abstractmethod
    def context(self):
        """Getter for the context of the message."""
        NotImplementedError("Cannot not instantiate abstract class CoseMessage")
