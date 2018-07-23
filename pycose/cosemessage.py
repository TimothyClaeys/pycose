import abc

import cbor

from pycose import attribute


class CoseMessage(attribute.Attribute, metaclass=abc.ABCMeta):
    cose_msg_id = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag):
        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls.cose_msg_id[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls, received):
        try:
            cbor_tag = cbor.loads(received).tag
            cose_obj = cbor.loads(received).value
        except AttributeError:
            raise AttributeError("Message was not tagged")

        if isinstance(cose_obj, list):
            # mac, encrypt or sig cose objects with tag, recipients or sig
            try:
                return cls.cose_msg_id[cbor_tag].from_cose_obj(cose_obj)
            except KeyError as e:
                raise KeyError("CBOR Tag is not recognized", e)

        else:
            raise TypeError("Message is not a COSE security message")

    @classmethod
    def from_cose_obj(cls, cose_obj):
        protected_header = cose_obj.pop(0)
        unprotected_header = cose_obj.pop(0)
        payload = cose_obj.pop(0)
        return cls(protected_header, unprotected_header, payload)

    def __init__(self, protected_header, unprotected_header, payload):
        super(CoseMessage, self).__init__()
        self.protected_header = protected_header
        self.unprotected_header = unprotected_header
        # can be plain or ciphertext
        self._payload = payload

    @property
    def payload(self):
        if isinstance(self._payload, str):
            return bytes(self._payload, 'utf-8')
        elif isinstance(self._payload, bytes):
            return self._payload
        else:
            raise TypeError("Payload doesn't have the correct encoding")

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

    @abc.abstractmethod
    def encode(self):
        raise NotImplementedError("Cannot not instantiate abstract class CoseMessage")

    @property
    @abc.abstractmethod
    def context(self):
        NotImplementedError("Cannot not instantiate abstract class CoseMessage")
