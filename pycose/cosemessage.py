import abc
import copy

import cbor

from pycose.coseattrs import CoseAttrs


class CoseMessage(metaclass=abc.ABCMeta):
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

        for key in decoded_protected_header:
            protected_header[key] = decoded_protected_header[key]

        for key in decoded_unprotected_header:
            unprotected_header[key] = decoded_unprotected_header[key]

        payload = cose_obj.pop(0)

        return cls(protected_header, unprotected_header, payload)

    def __init__(self, protected_header=CoseAttrs(), unprotected_header=CoseAttrs(), payload=None, external_aad=b''):
        self._protected_header = protected_header
        self._encoded_protected_header = self._encode_protected_header()
        self._unprotected_header = unprotected_header
        self._payload = payload
        self._external_aad = external_aad

    @property
    def protected_header(self):
        """Returns the protected header"""
        return self._protected_header

    @protected_header.setter
    def protected_header(self, new_value):
        """Sets the protected header value. Takes a dictionary object and copies its values in a CoseAttrs object."""
        for key in new_value:
            self._protected_header[key] = new_value[key]

    @property
    def encoded_protected_header(self):
        return self._encode_protected_header()

    @property
    def unprotected_header(self):
        return self._unprotected_header

    @unprotected_header.setter
    def unprotected_header(self, new_value):
        """Sets the unprotected header value."""
        for key in new_value:
            self._unprotected_header[key] = new_value[key]


    @property
    def external_aad(self):
        return self._external_aad

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

    def add_to_headers(self, label, value, where):
        if where == "PROTECTED":
            self.protected_header[label] = value

        if where == "UNPROTECTED":
            self.unprotected_header[label] = value

    def remove_from_headers(self, label):
        if not isinstance(label, str) and not isinstance(label, int):
            raise ValueError("label must be a string or an integer")

        if label in self._protected_header:
            del self._protected_header[label]

        if label in self._unprotected_header:
            del self._unprotected_header[label]

    def find_in_headers(self, label):
        if label in self._protected_header:
            return self._protected_header[label]
        elif label in self._unprotected_header:
            return self._unprotected_header[label]
        else:
            raise KeyError("Attribute not in headers " + str(label))

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

    def _encode_protected_header(self):
        """Encode the protected header. No action need to be taken for the unprotected header."""
        if len(self._protected_header) == 0:
            to_be_returned = bytes()
        else:
            to_be_returned = cbor.dumps(self._protected_header)

        return to_be_returned

    @abc.abstractmethod
    def encode(self):
        raise NotImplementedError("Cannot not instantiate abstract class CoseMessage")

    @property
    @abc.abstractmethod
    def context(self):
        """Getter for the context of the message."""
        NotImplementedError("Cannot not instantiate abstract class CoseMessage")
