import abc

import cbor

from pycose.attributes import CoseAttrs
from pycose.basicstructure import BasicCoseStructure


class CoseMessage(BasicCoseStructure, metaclass=abc.ABCMeta):
    """
    Parent class of all COSE message types.
    """

    cose_msg_id = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag):
        """Decorator to record all the CBOR tags dynamically"""

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls.cose_msg_id[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls, received):
        """Decode received COSE message based on the CBOR tag."""
        try:
            cbor_tag = cbor.loads(received).tag
            cose_obj = cbor.loads(received).value
        except AttributeError:
            raise AttributeError("Message was not tagged")

        if isinstance(cose_obj, list):
            try:
                return cls.cose_msg_id[cbor_tag].from_cose_obj(cose_obj)
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)

        else:
            raise TypeError("Message is not a COSE security message")

    @classmethod
    def from_cose_obj(cls, cose_obj):
        """Returns an initialized COSE message object."""
        protected_header = CoseAttrs()
        unprotected_header = CoseAttrs()

        try:
            decoded_protected_header = cbor.loads(cose_obj.pop(0))
        except ValueError:
            decoded_protected_header = {}

        try:
            decoded_unprotected_header = cose_obj.pop(0)
        except ValueError:
            decoded_unprotected_header = {}

        for k1 in decoded_protected_header:
            protected_header[k1] = decoded_protected_header[k1]

        for k2 in decoded_unprotected_header:
            unprotected_header[k2] = decoded_unprotected_header[k2]

        payload = cose_obj.pop(0)

        return cls(protected_header, unprotected_header, payload)

    def __init__(self, p_header=CoseAttrs(), u_header=CoseAttrs(), payload=b'', external_aad=b''):
        super(CoseMessage, self).__init__(p_header, u_header)
        self._payload = payload
        self._external_aad = external_aad

    @property
    def external_aad(self):
        return self._external_aad

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, new_value):
        if new_value is not None:
            if isinstance(new_value, bytes):
                self._payload = new_value
            elif isinstance(new_value, str):
                self._payload = bytes(new_value, 'utf-8')
            else:
                raise TypeError("Payload must be of type bytes or string")
        else:
            self._payload = bytes()

    @external_aad.setter
    def external_aad(self, new_external_aad):
        if new_external_aad is None or len(new_external_aad) == 0:
            self._external_aad = bytes()
        else:
            if isinstance(new_external_aad, str):
                self._external_aad = cbor.loads(new_external_aad)
            elif isinstance(new_external_aad, bytes):
                self._external_aad = new_external_aad
            else:
                raise TypeError("Input must be of type str or bytes")

    @abc.abstractmethod
    def encode(self):
        raise NotImplementedError("Cannot not instantiate abstract class CoseMessage")

    @property
    @abc.abstractmethod
    def context(self):
        """Getter for the context of the message."""
        NotImplementedError("Cannot not instantiate abstract class CoseMessage")
