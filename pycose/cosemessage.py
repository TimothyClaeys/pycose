import abc

import cbor

from pycose.attributes import CoseAttrs
from pycose.basicstructure import BasicCoseStructure
from pycose.exceptions import CoseUnknownAttributeName, CoseUnknownAttributeValue


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
    def from_cose_obj(cls, cose_obj):
        """Returns an initialized COSE message object."""
        protected_header = dict()
        unprotected_header = dict()

        try:
            decoded_protected_header = cbor.loads(cose_obj.pop(0))
        except (ValueError, EOFError):
            decoded_protected_header = {}

        try:
            decoded_unprotected_header = cose_obj.pop(0)
        except ValueError:
            decoded_unprotected_header = {}

        for k1 in decoded_protected_header:
            try:
                attr_name = [k for k, v in CoseAttrs._header_keys.items() if v == k1][0]
            except KeyError:
                raise CoseUnknownAttributeName()

            try:
                attr_val = \
                    [k for k, v in CoseAttrs._header_values[k1].items() if int(v) == decoded_protected_header[k1]][0]
            except KeyError:
                # we don't throw an exception here because some keys are not mapped on stored header values, e.g. iv
                attr_val = decoded_protected_header[k1]

            protected_header[attr_name] = attr_val

        for k2 in decoded_unprotected_header:
            try:
                attr_name = [k for k, v in CoseAttrs._header_keys.items() if v == k2][0]
            except KeyError:
                raise CoseUnknownAttributeName()

            try:
                attr_val = \
                    [k for k, v in CoseAttrs._header_values[k2].items() if int(v) == decoded_unprotected_header[k2]][0]
            except KeyError:
                # we don't throw an exception here because some keys are not mapped on stored header values, e.g. iv
                attr_val = decoded_unprotected_header[k2]

            unprotected_header[attr_name] = attr_val

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
        if isinstance(new_value, bytes):
            self._payload = new_value
        elif isinstance(new_value, str):
            self._payload = new_value.encode('utf-8')
        else:
            raise TypeError("Payload must be of type bytes or string")


    @external_aad.setter
    def external_aad(self, new_external_aad):
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
